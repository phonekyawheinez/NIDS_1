 python -m venv .venv
 .\.venv\Scripts\Activate
 deactivate





python .\scripts\pyspark_part3_multiclass_classification.py

python .\scripts\sniffer.py

spark-submit realtime_processor.py
python .\scripts\realtime_processor.py


streamlit run dashboard.py



