import json
import os
import pandas as pd

NEW_COLOR = "#d4edda"  # green highlight

def load_baseline(path):
    with open(path, 'r') as f:
        data = json.load(f)
    rows = []
    for file, secrets in data.get('results', {}).items():
        for secret in secrets:
            rows.append({
                'File': file,
                'Line': secret.get('line_number', ''),
                'Type': secret.get('type', ''),
                'Verified': secret.get('is_verified', ''),
                'Hashed Secret': secret.get('hashed_secret', '')
            })
    return pd.DataFrame(rows)

# --- Paths ---
NEW_PATH = '.secrets.baseline'
OLD_PATH = '.secrets.baseline.old'

new_df = load_baseline(NEW_PATH)

if os.path.exists(OLD_PATH):
    old_df = load_baseline(OLD_PATH)
else:
    old_df = pd.DataFrame(columns=['File','Line','Type','Verified','Hashed Secret'])

# --- Detect new rows ---
KEYS = ['File','Line','Type','Verified','Hashed Secret']
new_df = new_df.fillna("").astype(str)  # normalize
old_df = old_df.fillna("").astype(str)

# turn into sets of tuples
old_set = set(map(tuple, old_df[KEYS].values.tolist()))

# mark new
statuses = []
for row in new_df[KEYS].itertuples(index=False, name=None):
    statuses.append("New" if row not in old_set else "Existing")

new_df["Status"] = statuses

# shorten secret for display
new_df['Hashed Secret'] = new_df['Hashed Secret'].str[:8] + '...'

# --- Counts ---
total = len(new_df)
new_count = (new_df["Status"] == "New").sum()

# --- HTML generation ---
def row_to_html(idx, row):
    row_class = " class='new'" if row['Status'] == 'New' else ''
    cells = [
        f"<td>{idx}</td>",
        f"<td>{row['File']}</td>",
        f"<td>{row['Line']}</td>",
        f"<td>{row['Type']}</td>",
        f"<td>{row['Verified']}</td>",
        f"<td>{row['Hashed Secret']}</td>",
    ]
    return f"<tr{row_class}>" + "".join(cells) + "</tr>"

headers = (
    "<tr>"
    "<th>Index</th><th>File</th><th>Line</th><th>Type</th>"
    "<th>Verified</th><th>Hashed Secret</th>"
    "</tr>"
)

rows_html = "\n".join(row_to_html(i, row) for i, row in enumerate(new_df.to_dict("records"), start=1))
html_table = f"<table class='table'><thead>{headers}</thead><tbody>{rows_html}</tbody></table>"

style = f"""
<style>
  .table {{
    border-collapse: collapse;
    width: 100%;
    font-family: Arial, sans-serif;
  }}
  .table th, .table td {{
    border: 1px solid #ddd;
    padding: 8px;
  }}
  .table tr:nth-child(even){{background-color: #f9f9f9;}}
  .table tr:hover {{background-color: #d1e7fd;}}
  .table th {{
    background-color: #4CAF50;
    color: white;
    text-align: left;
  }}
  .new {{ background-color: {NEW_COLOR} !important; }} /* highlight new rows */
  p {{
    font-family: Arial, sans-serif;
    font-size: 16px;
  }}
</style>
"""

# Two counts
counts_html = f"""
<p><strong>Total Secrets Found: {total}</strong></p>
<p><strong>New Secrets: {new_count}</strong></p>
"""

with open('secrets_baseline.html', 'w') as f:
    f.write(style + counts_html + html_table)

print(f"HTML file 'secrets_baseline.html' generated with {total} secrets listed! ({new_count} new, highlighted in green)")
