import sqlite3

conn = sqlite3.connect(r"C:\CIS 382 PROJECT\example.db")
conn.execute("DROP TABLE IF EXISTS user")
conn.commit()
conn.close()
print("Done")