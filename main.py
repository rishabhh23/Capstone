import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import requests
from datetime import datetime, timedelta
import plotly.express as px
import seaborn as sns
import json
from datetime import datetime
from api.apiCalls import check_ip_reputation, check_ip_quality
from api.passwordManager import password_manager
from api.vulnScanner import vuln_scanner

# Page configuration
st.set_page_config(page_title="GridSec : Cybersecurity Dashboard", layout="wide", page_icon="🛡️")

# Dummy data
np.random.seed(42)
def generate_dummy_data():
    data = pd.DataFrame({
        'Incident_ID': range(1, 101),
        'Risk_Level': np.random.choice(['Low', 'Medium', 'High', 'Critical'], size=100, p=[0.2, 0.4, 0.3, 0.1]),
        'Attack_Type': np.random.choice(['Phishing', 'Malware', 'DDoS', 'Ransomware', 'Insider Threat', 'SQL Injection'], size=100),
        'Loss_Amount($)': np.random.randint(1000, 50000, size=100),
        'Date': pd.date_range('2024-01-01', periods=100, freq='D'),
        'Source_IP': [f"192.168.{np.random.randint(0,255)}.{np.random.randint(1,255)}" for _ in range(100)],
        'Target_Asset': np.random.choice(['Web Server', 'Database', 'Workstation', 'Firewall', 'Cloud Storage'], size=100),
        'Status': np.random.choice(['Open', 'In Progress', 'Resolved', 'Escalated'], size=100),
        'Response_Time(min)': np.random.randint(5, 360, size=100)
    })
    return data

data = generate_dummy_data()

# Streamlit app
st.title("GridSec : 🛡️ Advanced Cybersecurity Risk Assessment Dashboard")

# Sidebar filters
st.sidebar.title("🔍 Filter Options")
selected_risk = st.sidebar.multiselect(
    'Select Risk Level', 
    options=data['Risk_Level'].unique(), 
    default=data['Risk_Level'].unique()
)

selected_attack = st.sidebar.multiselect(
    'Select Attack Type', 
    options=data['Attack_Type'].unique(), 
    default=data['Attack_Type'].unique()
)

selected_status = st.sidebar.multiselect(
    'Select Incident Status', 
    options=data['Status'].unique(), 
    default=data['Status'].unique()
)

date_range = st.sidebar.date_input(
    "Select Date Range",
    value=[data['Date'].min(), data['Date'].max()],
    min_value=data['Date'].min(),
    max_value=data['Date'].max()
)

# Threat intelligence lookup in sidebar
st.sidebar.title("🔎 Threat Intelligence Lookup")
lookup_type = st.sidebar.selectbox("Lookup Type", ["IP Address", "Domain", "File Hash"])
lookup_value = st.sidebar.text_input(f"Enter {lookup_type}")

# Filter data based on selections
filtered_data = data[
    (data['Risk_Level'].isin(selected_risk)) & 
    (data['Attack_Type'].isin(selected_attack)) & 
    (data['Status'].isin(selected_status)) &
    (data['Date'] >= pd.to_datetime(date_range[0])) & 
    (data['Date'] <= pd.to_datetime(date_range[1]))
]

# Layout columns for KPIs
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Incidents", len(filtered_data))
with col2:
    st.metric("High/Critical Risks", 
             len(filtered_data[filtered_data['Risk_Level'].isin(['High', 'Critical'])]))
with col3:
    st.metric("Total Loss ($)", f"${filtered_data['Loss_Amount($)'].sum():,}")
with col4:
    avg_response = filtered_data['Response_Time(min)'].mean()
    st.metric("Avg Response Time", f"{avg_response:.1f} mins")

# Main tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 Overview", 
        "📈 Trends", 
        "🌐 Geo", 
        "🛡️ Threat Intel",
        "🔑 Password Manager",
        "🕷️ Vuln Scanner"
    ])

with tab1:
    st.subheader("Incident Overview")
    
    # Two columns for charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk level pie chart using Plotly for interactivity
        st.markdown("### Risk Level Distribution")
        risk_count = filtered_data['Risk_Level'].value_counts().reset_index()
        risk_count.columns = ['Risk_Level', 'Count']
        fig = px.pie(risk_count, values='Count', names='Risk_Level', 
                     color='Risk_Level',
                     color_discrete_map={'Low':'green', 'Medium':'orange', 
                                       'High':'red', 'Critical':'darkred'})
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Attack type treemap
        st.markdown("### Attack Type Distribution")
        attack_counts = filtered_data['Attack_Type'].value_counts().reset_index()
        attack_counts.columns = ['Attack_Type', 'Count']
        fig = px.treemap(attack_counts, path=['Attack_Type'], values='Count')
        st.plotly_chart(fig, use_container_width=True)
    
    # Status distribution
    st.markdown("### Incident Status")
    status_counts = filtered_data['Status'].value_counts().reset_index()
    status_counts.columns = ['Status', 'Count']
    fig = px.bar(status_counts, x='Status', y='Count', color='Status')
    st.plotly_chart(fig, use_container_width=True)

with tab2:
    st.subheader("Temporal Trends")
    
    # Time series charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Incidents Over Time")
        time_series = filtered_data.groupby('Date').size().reset_index()
        time_series.columns = ['Date', 'Count']
        fig = px.line(time_series, x='Date', y='Count', 
                      title="Daily Incident Count")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Loss Amount Over Time")
        loss_series = filtered_data.groupby('Date')['Loss_Amount($)'].sum().reset_index()
        fig = px.area(loss_series, x='Date', y='Loss_Amount($)',
                      title="Daily Financial Loss")
        st.plotly_chart(fig, use_container_width=True)
    
    # Heatmap of incidents by day of week and hour
    st.markdown("### Incident Heatmap (Day vs Risk Level)")
    filtered_data['Day_of_Week'] = filtered_data['Date'].dt.day_name()
    filtered_data['Hour'] = np.random.randint(0, 24, len(filtered_data))  # Simulate hour
    heatmap_data = pd.crosstab(filtered_data['Day_of_Week'], 
                              filtered_data['Risk_Level'])
    days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    heatmap_data = heatmap_data.reindex(days_order)
    fig, ax = plt.subplots(figsize=(10, 4))
    sns.heatmap(heatmap_data, cmap="YlOrRd", annot=True, fmt="d", ax=ax)
    st.pyplot(fig)

with tab3:
    st.subheader("Geographical and Asset Analysis")
    
    # Simulated geo data for demo
    countries = ['USA', 'China', 'Germany', 'UK', 'Russia', 'India', 'Brazil', 'Australia']
    filtered_data['Source_Country'] = np.random.choice(countries, size=len(filtered_data))
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Attacks by Country")
        country_counts = filtered_data['Source_Country'].value_counts().reset_index()
        country_counts.columns = ['Country', 'Count']
        fig = px.choropleth(country_counts, 
                            locations='Country',
                            locationmode='country names',
                            color='Count',
                            hover_name='Country',
                            color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Target Assets")
        asset_counts = filtered_data['Target_Asset'].value_counts().reset_index()
        asset_counts.columns = ['Asset', 'Count']
        fig = px.bar(asset_counts, x='Asset', y='Count', color='Asset')
        st.plotly_chart(fig, use_container_width=True)
    
    # IP address analysis
    st.markdown("### Top Source IPs")
    top_ips = filtered_data['Source_IP'].value_counts().head(10).reset_index()
    top_ips.columns = ['IP Address', 'Count']
    st.dataframe(top_ips)

# SIMULATED DATA.
# with tab4:
#     st.subheader("Threat Intelligence")
    
#     if lookup_value:
#         st.info(f"Looking up {lookup_type}: {lookup_value}")
        
#         # Simulated API responses (in a real app, you'd call actual APIs)
#         if lookup_type == "IP Address":
#             # Simulated VirusTotal API response
#             st.markdown("#### IP Reputation Analysis")
#             col1, col2, col3 = st.columns(3)
#             with col1:
#                 st.metric("Malicious Score", "8/10", "-2 from last week")
#             with col2:
#                 st.metric("Associated Threats", "3", "Phishing, Malware")
#             with col3:
#                 st.metric("Country", "Russia", "")
            
#             st.markdown("#### Historical Activity")
#             activity_data = pd.DataFrame({
#                 'Date': pd.date_range('2024-01-01', periods=30),
#                 'Activity': np.random.randint(1, 100, 30)
#             })
#             fig = px.line(activity_data, x='Date', y='Activity', 
#                           title="Historical Activity from this IP")
#             st.plotly_chart(fig, use_container_width=True)
            
#         elif lookup_type == "Domain":
#             st.markdown("#### Domain Analysis")
#             col1, col2, col3 = st.columns(3)
#             with col1:
#                 st.metric("Risk Score", "High", "75/100")
#             with col2:
#                 st.metric("Creation Date", "2023-05-12", "1 year old")
#             with col3:
#                 st.metric("SSL Valid", "No", "Potential risk")
            
#         elif lookup_type == "File Hash":
#             st.markdown("#### File Hash Analysis")
#             col1, col2, col3 = st.columns(3)
#             with col1:
#                 st.metric("Detection Rate", "45/70", "64% malicious")
#             with col2:
#                 st.metric("File Type", "Executable", "PE32")
#             with col3:
#                 st.metric("First Seen", "2024-02-15", "1 month ago")
            
#             st.markdown("#### Associated Threats")
#             threats = pd.DataFrame({
#                 'Vendor': ['Microsoft', 'Kaspersky', 'McAfee', 'Symantec'],
#                 'Detection': ['Trojan:Win32/Wacatac', 'HEUR:Trojan.Win32.Generic', 
#                              'Artemis!Trojan', 'Trojan.Gen.2'],
#                 'Severity': ['High', 'High', 'Medium', 'High']
#             })
#             st.dataframe(threats)
#     else:
#         st.warning("Enter a value in the sidebar to perform threat intelligence lookup")

# REAL DATA FETCHING
with tab4:
    st.subheader("Threat Intelligence")
    
    if lookup_value:
        st.info(f"Looking up {lookup_type}: {lookup_value}")
        
        if lookup_type == "IP Address":
            # Real API calls
            vt_results = check_ip_reputation(lookup_value)
            ipq_results = check_ip_quality(lookup_value)
            
            if 'error' not in vt_results:
                # Display VirusTotal results
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Malicious Score", 
                            f"{vt_results['malicious']}/90+ vendors",
                            help="Number of security vendors flagging this IP as malicious")
                
                with col2:
                    st.metric("Location", 
                            f"{vt_results.get('country', 'Unknown')}",
                            f"ISP: {vt_results.get('as_owner', 'Unknown')}")
                
                with col3:
                    st.metric("Suspicious Indicators", 
                            f"{ipq_results.get('fraud_score', 0)}/100 risk",
                            f"Proxy: {ipq_results.get('proxy', False)} | VPN: {ipq_results.get('vpn', False)}")
                
                # Detailed analysis
                with st.expander("Detailed Threat Analysis"):
                    st.json(vt_results['raw_data'])  # Full API response
            else:
                st.error(f"VirusTotal Error: {vt_results['error']}")

with tab5:
    password_manager()

with tab6:
    vuln_scanner()

# Display data table with expander
with st.expander("📋 View Filtered Incident Data", expanded=False):
    st.dataframe(filtered_data.sort_values('Risk_Level', ascending=False))

# Provide download button for filtered data
st.sidebar.download_button(
    label="📥 Download Filtered Data as CSV",
    data=filtered_data.to_csv(index=False),
    file_name='filtered_cybersecurity_data.csv',
    mime='text/csv',
)

# Add a footer
st.sidebar.markdown("---")
st.sidebar.markdown("🔒 Final Year Project - Cybersecurity Dashboard")
st.sidebar.markdown("⚠️ Note: This dashboard uses simulated data for demonstration purposes")