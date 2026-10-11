import psycopg2
conn = psycopg2.connect("postgresql://voting_admin:securepassword@127.0.0.1:5432/voting")
cur = conn.cursor()
cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
print(cur.fetchall())
