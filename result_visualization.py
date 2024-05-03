import pandas as pd
import matplotlib.pyplot as plt

# Read the CSV file
df = pd.read_csv('domain_resolvability_check.csv')

# Calculate percentages
ipv6_resolvable_percentage = df['IPv6 Resolvable'].value_counts(normalize=True) * 100
ipv4_presence = df['IPv4'].notna()
ipv4_presence_percentage = ipv4_presence.value_counts(normalize=True) * 100

# Bar graph for IPv6 Resolvable
plt.figure(figsize=(12, 6))

plt.subplot(1, 2, 1)
ipv6_resolvable_percentage.plot(kind='bar', color=['blue', 'orange'])
plt.title('Percentage of Domains by IPv6 Resolvability')
plt.xlabel('IPv6 Resolvable')
plt.ylabel('Percentage')
plt.xticks(range(len(ipv6_resolvable_percentage)), ['False', 'True'], rotation=0)

# Bar graph for IPv4 Presence
plt.subplot(1, 2, 2)
ipv4_presence_percentage.plot(kind='bar', color=['red', 'green'])
plt.title('Percentage of Domains by IPv4 Presence')
plt.xlabel('IPv4 Presence')
plt.ylabel('Percentage')
plt.xticks(range(len(ipv4_presence_percentage)), ['False', 'True'], rotation=0)

plt.tight_layout()
plt.savefig('ipv6_ipv4_presence.png')  # Save the graph as a PNG file
plt.close()
