import pandas as pd
import matplotlib.pyplot as plt

# Read data from CSV file
df = pd.read_csv('domain_resolvability_10k.csv')

# Calculate the total number of domains
total_domains = len(df)

# Count the number of domains that are IPv4 resolvable, IPv6 resolvable, and neither
ipv4_resolvable_count = df['IPv4 Resolvable'].sum()
ipv6_resolvable_count = df['IPv6 Resolvable'].sum()
neither_resolvable_count = total_domains - (ipv4_resolvable_count + ipv6_resolvable_count)

# Calculate the percentage of domains that are IPv4 resolvable, IPv6 resolvable, and neither
ipv4_resolvable_percentage = (ipv4_resolvable_count / total_domains) * 100
ipv6_resolvable_percentage = (ipv6_resolvable_count / total_domains) * 100
neither_resolvable_percentage = (neither_resolvable_count / total_domains) * 100

# Create a bar graph
labels = ['IPv4 only', 'IPv6 and IPv4', 'Unreachable']
percentages = [ipv4_resolvable_percentage, ipv6_resolvable_percentage, neither_resolvable_percentage]

plt.bar(labels, percentages, color=['green', 'yellow', 'red'])
plt.xlabel('Resolvability')
plt.ylabel('Percentage')
plt.title('Percentage of Domains that are IPv4, IPv6, or Neither Resolvable')
plt.ylim(0, 100)  # Set y-axis limits to ensure percentages are displayed properly

# Save the graph as a PNG file
plt.savefig('ipv4_ipv6_resolvability.png')

# Show the graph
plt.show()
