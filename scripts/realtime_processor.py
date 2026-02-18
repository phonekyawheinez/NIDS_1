import os
import sys
import json
import shutil
from pyspark.sql import SparkSession
from pyspark.ml import PipelineModel
from pyspark.sql.functions import from_json, col, udf, current_timestamp, lit, create_map
from pyspark.sql.types import StructType, StructField, IntegerType, FloatType, StringType, DoubleType, LongType
from itertools import chain

# ============================================================================
# 1. INITIALIZE SPARK (DOCKER OPTIMIZED)
# ============================================================================
# No need for manual ENV paths; Dockerfile.spark handles JAVA_HOME and SPARK_HOME.
# 1. INITIALIZE SPARK
spark = SparkSession.builder \
    .appName("NIDS_Zeek_Processor") \
    .config("spark.driver.memory", "1g") \
    .config("spark.sql.parquet.enableVectorizedReader", "false") \
    .config("spark.sql.parquet.mergeSchema", "true") \
    .config("spark.sql.legacy.parquet.nanosAsLong", "true") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

# 2. LOAD MODEL & LABELS
BASE_DIR = "/app"
MODEL_PATH = os.path.join(BASE_DIR, "saved_models", "nids_multiclass_model")
LABELS_PATH = os.path.join(BASE_DIR, "saved_models", "label_mapping.json")

print(f"📥 Loading model from: {MODEL_PATH}")

try:
    model = PipelineModel.load(MODEL_PATH)
    with open(LABELS_PATH, "r") as f:
        labels_list = json.load(f)

    # Create the mapping dictionary for the UDF
    label_dict = {float(i): label for i, label in enumerate(labels_list)}
    # Define a UDF to map the numeric prediction to a string label
    label_udf = udf(lambda x: label_dict.get(x, "Unknown"), StringType())

    print("✓ Model and Label Mapping loaded successfully.")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    sys.exit(1)

# ============================================================================
# 3. DEFINE ZEEK LOG SCHEMA
# ============================================================================
# This matches the JSON output from Zeek's conn.log
zeek_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", LongType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", LongType(), True),
    StructField("proto", StringType(), True),
    StructField("service", StringType(), True),
    StructField("duration", DoubleType(), True),
    StructField("orig_bytes", LongType(), True),
    StructField("resp_bytes", LongType(), True),
    StructField("conn_state", StringType(), True),
    StructField("orig_pkts", LongType(), True),
    StructField("resp_pkts", LongType(), True)
])

# ============================================================================
# 4. STREAMING INPUT (FROM ZEEK LOGS)
# ============================================================================
print("📡 Monitoring /app/zeek_logs for new connection logs...")

# Read JSON files as they appear in the folder
input_df = spark.readStream \
    .format("json") \
    .schema(zeek_schema) \
    .option("maxFilesPerTrigger", 1) \
    .option("latestFirst", "false") \
    .load("/app/zeek_logs/")
# This folder is mounted in docker-compose

# ============================================================================
# 5. FEATURE MAPPING (Zeek -> ML Model)
# ============================================================================
# We map available Zeek columns to the features your model expects.
# MISSING FEATURES are filled with 0 to prevent crashes.
processed_df = input_df \
    .withColumn("dur", col("duration").cast(DoubleType())) \
    .withColumn("sbytes", col("orig_bytes").cast(LongType())) \
    .withColumn("dbytes", col("resp_bytes").cast(LongType())) \
    .withColumn("spkts", col("orig_pkts").cast(LongType())) \
    .withColumn("dpkts", col("resp_pkts").cast(LongType())) \
    .na.fill(0)
# Handle nulls if Zeek doesn't record bytes/duration

# Fill missing columns that the model expects but Zeek doesn't provide by default
# (These would require a custom Zeek script to calculate)
missing_cols = [
    "sttl", "dttl", "sloss", "dloss", "sload", "dload", "swin", "dwin",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit",
    "stime", "ltime", "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd"
]

for c in missing_cols:
    processed_df = processed_df.withColumn(c, lit(0).cast(DoubleType())) # Cast to Double for ML safety

# 6. PREDICTION & OUTPUT
# Apply model transformations
predictions = model.transform(processed_df)

final_stream = predictions.withColumn("attack_type", label_udf(col("prediction"))) \
    .select(
        current_timestamp().alias("timestamp"),
        col("id.orig_h").alias("src_ip"),
        col("id.resp_h").alias("dst_ip"),
        col("proto"),
        col("attack_type")
    )

# Output Setup
output_path = "/app/stream_output"
checkpoint_path = "/app/stream_checkpoint"

# Ensure clean start
if os.path.exists(output_path):
    try:
        shutil.rmtree(output_path)
    except:
        pass

if os.path.exists(checkpoint_path):
    try:
        shutil.rmtree(checkpoint_path)
    except:
        pass

print("🚀 Starting Stream Processing...")

query = final_stream.writeStream \
    .format("json") \
    .outputMode("append") \
    .option("path", output_path) \
    .option("checkpointLocation", "/app/stream_checkpoint") \
    .start()

query.awaitTermination()