from src.hybrid_waf.ai.anomaly_detector import train_model
import numpy as np

# generate normal traffic
data = np.random.normal(size=(2000,5))

train_model(data)

print("AI model trained")