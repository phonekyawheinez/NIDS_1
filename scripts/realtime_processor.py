import os
import sys
import json
import shutil
import glob
import findspark

# ============================================================================
# 1. WINDOWS & SPARK ENVIRONMENT SETUP (PATH SANITIZATION)
# ============================================================================
# Use 'r' before strings to handle Windows backslashes correctly.
# DOUBLE CHECK these folders in File Explorer!
os.environ['JAVA_HOME'] = r"C:\Program Files\Eclipse Adoptium\jdk-17.0.17.10-hotspot"
os.environ['SPARK_HOME'] = r"C:\Spark"
os.environ['HADOOP_HOME'] = r"C:\hadoop"

# Force add the BIN folders to the PATH so Windows can find java.exe and winutils.exe
os.environ['PATH'] = (
    os.path.join(os.environ['JAVA_HOME'], 'bin') + os.pathsep +
    os.path.join(os.environ['SPARK_HOME'], 'bin') + os.pathsep +
    os.path.join(os.environ['HADOOP_HOME'], 'bin') + os.pathsep +
    os.environ['PATH']
)

# Ensure Spark uses your PyCharm Virtual Environment's Python
os.environ['PYSPARK_PYTHON'] = sys.executable
os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable

# Manually link Python libraries
sys.path.append(os.path.join(os.environ['SPARK_HOME'], 'python'))

try:
    # Auto-detect the py4j zip version
    py4j_zip = glob.glob(os.path.join(os.environ['SPARK_HOME'], 'python', 'lib', 'py4j-*.zip'))[0]
    sys.path.append(py4j_zip)
    print(f"✓ Successfully linked: {os.path.basename(py4j_zip)}")
except IndexError:
    print(r"Error: Could not find py4j zip file in C:\Spark\python\lib")
    sys.exit(1)

# Initialize findspark ONLY after paths are set
findspark.init()

from pyspark.sql import SparkSession
# ... rest of your imports
from pyspark.ml import PipelineModel
from pyspark.sql.functions import from_json, col, udf, current_timestamp, split , create_map, lit
from pyspark.sql.types import StructType, StructField, IntegerType, FloatType, StringType
from itertools import chain

# Windows compatibility fix for socket streaming
if sys.platform == "win32":
    import socketserver
    if not hasattr(socketserver, 'UnixStreamServer'):
        socketserver.UnixStreamServer = socketserver.TCPServer

# ============================================================================
# 2. INITIALIZE SPARK
# ============================================================================
# Remove the 'extraJavaOptions' that caused the crash
spark = SparkSession.builder \
    .appName("NIDS_RealTime") \
    .config("spark.driver.memory", "2g") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

# ============================================================================
# 3. LOAD MODEL & LABELS
# ============================================================================
# Ensure these paths point to where your Part 3 script saved the outputs
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Build the absolute path to the model (going up one level from scripts to root)
MODEL_PATH = os.path.join(SCRIPT_DIR, "..", "saved_models", "nids_multiclass_model")
LABELS_PATH = os.path.join(SCRIPT_DIR, "..", "saved_models", "label_mapping.json")

# Convert to a format Spark likes for Windows (replacing \ with /)
MODEL_PATH = MODEL_PATH.replace("\\", "/")

print(f"Loading model from: {MODEL_PATH}")

try:
    model = PipelineModel.load(MODEL_PATH)
    with open(LABELS_PATH, "r") as f:
        labels_list = json.load(f)

    # Create a native Spark Map: {0: "Normal", 1: "Generic", ...}
    label_map = create_map([lit(x) for x in chain(*enumerate(labels_list))])
    print("✓ Model and native label map loaded successfully.")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    sys.exit(1)

# UDF to map numeric prediction back to category name (e.g., 0 -> "Normal")
get_label_udf = udf(lambda x: labels_list[int(x)] if x is not None else "Unknown", StringType())

# ============================================================================
# 4. DATA SCHEMA (26 features matching your Part 3 training)
# ============================================================================
schema = StructType([
    StructField("dur", FloatType(), True),
    StructField("sbytes", IntegerType(), True),
    StructField("dbytes", IntegerType(), True),
    StructField("sttl", IntegerType(), True),
    StructField("dttl", IntegerType(), True),
    StructField("sloss", IntegerType(), True),
    StructField("dloss", IntegerType(), True),
    StructField("sload", FloatType(), True),
    StructField("dload", FloatType(), True),
    StructField("spkts", IntegerType(), True),
    StructField("dpkts", IntegerType(), True),
    StructField("swin", IntegerType(), True),
    StructField("dwin", IntegerType(), True),
    StructField("smeansz", IntegerType(), True),
    StructField("dmeansz", IntegerType(), True),
    StructField("trans_depth", IntegerType(), True),
    StructField("res_bdy_len", IntegerType(), True),
    StructField("sjit", FloatType(), True),
    StructField("djit", FloatType(), True),
    StructField("stime", FloatType(), True),
    StructField("ltime", FloatType(), True),
    StructField("sintpkt", FloatType(), True),
    StructField("dintpkt", FloatType(), True),
    StructField("tcprtt", FloatType(), True),
    StructField("synack", FloatType(), True),
    StructField("ackdat", FloatType(), True),
    StructField("is_sm_ips_ports", IntegerType(), True),
    StructField("ct_state_ttl", IntegerType(), True),
    StructField("ct_flw_http_mthd", IntegerType(), True)
])

# ============================================================================
# 5. STREAMING PIPELINE
# ============================================================================
print("📡 Waiting for sniffer stream on localhost:9999...")

raw_stream = spark.readStream \
    .format("socket") \
    .option("host", "localhost") \
    .option("port", 8888) \
    .load()

# Parse JSON strings coming from the sniffer script
json_stream = raw_stream.select(from_json(col("value"), schema).alias("data")).select("data.*")
json_stream = json_stream.na.fill(0)

# Apply the machine learning model to the live stream
predictions = model.transform(json_stream)

# Format the results for the Streamlit dashboard
final_stream = predictions.select(
    current_timestamp().alias("timestamp"),
    col("sbytes"),
    col("sttl"),
    # Map the numeric prediction directly without using a UDF
    # label_map.getItem(col("prediction").cast("integer")).alias("attack_type")
    label_map.getItem(col("prediction").cast("integer")).alias("attack_type")
)
# Clean folders from previous runs to avoid state conflicts
# ============================================================================
# 6. WORKSPACE CLEANUP (STABLE VERSION)
# ============================================================================
output_path = "../stream_output"
checkpoint_path = "../stream_checkpoint"

def safe_cleanup(path):
    """Deletes contents of a folder without deleting the folder itself."""
    if os.path.exists(path):
        print(f"🧹 Attempting to clean: {path}")
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)  # Delete individual file
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path) # Delete sub-folders
            except Exception as e:
                # If Streamlit is using a file, we skip it instead of crashing
                print(f"⚠️ Skipping busy file (being used by Dashboard): {filename}")

# Run the safe cleanup on both folders
safe_cleanup(output_path)
safe_cleanup(checkpoint_path)

# Ensure folders exist before Spark starts
os.makedirs(output_path, exist_ok=True)
os.makedirs(checkpoint_path, exist_ok=True)

# Write the predictions to JSON files for the dashboard to read
query = final_stream.writeStream \
    .format("json") \
    .option("path", output_path) \
    .option("checkpointLocation", checkpoint_path) \
    .outputMode("append") \
    .start()

print("🚀 Real-time analysis active. Open your Dashboard now.")
query.awaitTermination()