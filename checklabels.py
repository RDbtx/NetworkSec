import pandas as pd

df = pd.read_csv("/Users/riccardo/Desktop/NetworkSec/src/model/dataset/1-http-flood/pcap1-caddy-l.csv")
labels = sorted(df["Label"].dropna().unique())
print(labels)