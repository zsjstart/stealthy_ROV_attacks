import glob
import json
import pandas as pd

results = []
for file in glob.glob("results/*.json"):
    with open(file, "r") as f:
        results.append(json.load(f))

df = pd.DataFrame(results)
print(df.groupby(["method", "adoption_rate"])[["impact", "direct_impact", "indirect_impact"]].mean())
