import os
import pandas as pd
import matplotlib.pyplot as plt

# Read data from CSV file
df = pd.read_csv('domains.csv')

# Count the number of domains that are IPv4 resolvable, IPv6 resolvable, and neither
ipv4_resolvable_count = df['IPv4 Resolvable'].sum()
ipv6_resolvable_count = df['IPv6 Resolvable'].sum()
total_domains = len(df)

# Calculate the percentage of domains that are IPv4 resolvable, IPv6 resolvable, and neither
ipv4_resolvable_percentage = (ipv4_resolvable_count / total_domains) * 100
ipv6_resolvable_percentage = (ipv6_resolvable_count / total_domains) * 100
neither_resolvable_percentage = 100 - ipv4_resolvable_percentage - ipv6_resolvable_percentage

# Create labels and percentages for the pie chart
labels = ['IPv4 Resolvable', 'IPv6 Resolvable', 'Neither']
percentages = [ipv4_resolvable_percentage, ipv6_resolvable_percentage, neither_resolvable_percentage]

# Create a pie chart
plt.pie([float(x) for x in percentages], labels=labels, autopct='%1.1f%%', colors=['blue', 'green', 'red'])
plt.title('Percentage of Domains by Resolvability')

# Specify the full path where you want to save the pie chart PNG file
output_path = os.path.join(os.getcwd(), 'resolvability_pie_chart.png')

# Save the pie chart as a PNG file
plt.savefig(output_path)

# Show the pie chart
plt.show()
