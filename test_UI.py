import pandas as pd
import json
import dash
from dash import dcc, html, dash_table
import plotly.express as px

def label_cvss_score(score):
    if score == 0:
        return "None"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"

# Load both ranking engine JSON files
with open('ranking_engine_1.json', 'r') as f1:
    data1 = json.load(f1)

with open('ranking_engine_2.json', 'r') as f2:
    data2 = json.load(f2)

df1 = pd.DataFrame(data1)
df2 = pd.DataFrame(data2)
# Add severity labels
# df1['severity'] = df1['risk_score'].apply(label_cvss_score)
# df2['severity'] = df2['risk_score'].apply(label_cvss_score)
df1['severity'] = df1['max_cvss'].apply(label_cvss_score)
df2['severity'] = df2['max_cvss'].apply(label_cvss_score)


app = dash.Dash(__name__)

# Engine 1 graphs Original
# engine1_cvss_pie = px.pie(df1, names='package', values='cvss_count', title='Engine 1: CVSS Count')
# engine1_risk_bar = px.bar(df1, x='package', y='risk_score', title='Engine 1: Risk Score')

# -- CVSS Count Table --
cvss_count_table = dash_table.DataTable(
    columns=[{"name": col, "id": col} for col in ['package', 'cvss_count']],
    data=df1[['package', 'cvss_count']].to_dict('records'),
    style_table={'width': '50%'},
    style_cell={'textAlign': 'center'},
)


# Engine 2 graphs Original
# engine2_downloads_pie = px.pie(df2, names='package', values='downloads', title='Engine 2: Downloads')
# engine2_risk_bar = px.bar(df2, x='package', y='risk_score', title='Engine 2: Risk Score')

# Engine 1 graphs
engine1_cvss_pie = px.pie(df1, names='package', values='cvss_count', title='Engine 1: CVSS Count')
engine1_risk_bar = px.bar(
    df1, x='package', y='risk_score',
    color='severity',
    title='Engine 1: Risk Score',
    color_discrete_map={
        'None': 'gray',
        'Low': 'green',
        'Medium': 'orange',
        'High': 'red',
        'Critical': 'darkred'
    }
)

# Engine 2 graphs
engine2_downloads_pie = px.pie(df2, names='package', values='downloads', title='Engine 2: Downloads')
engine2_risk_bar = px.bar(
    df2, x='package', y='risk_score',
    color='severity',
    title='Engine 2: Risk Score',
    color_discrete_map={
        'None': 'gray',
        'Low': 'green',
        'Medium': 'orange',
        'High': 'red',
        'Critical': 'darkred'
    }
)


# Tabs layout
app.layout = html.Div([
    html.H1("📊 Python Vulnerability Ranking Dashboard"),
    dcc.Tabs([
        dcc.Tab(label='Engine 1', children=[
            dcc.Graph(figure=engine1_cvss_pie),
            dcc.Graph(figure=engine1_risk_bar),
            
            # Newly added
            html.H1("📋 CVSS Counts from Engine 1"),
            cvss_count_table,
        ]),
        dcc.Tab(label='Engine 2', children=[
            dcc.Graph(figure=engine2_downloads_pie),
            dcc.Graph(figure=engine2_risk_bar),
        ])
    ])
])

if __name__ == '__main__':
    app.run(debug=True)
