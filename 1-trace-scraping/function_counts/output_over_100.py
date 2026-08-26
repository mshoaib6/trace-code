import pickle
import matplotlib.pyplot as plt

with open('function_counts/function_counts_new.pkl', 'rb') as f:
    function_calls = pickle.load(f)

limit = 100

fcall_list = list(function_calls.items())
fcall_list.sort(key = lambda x: x[1], reverse = True)
over_100 = []
remaining = 0
non_remaining = 0
for item, count in fcall_list:
    if count >= limit:
        non_remaining += count
        over_100.append((item, count)) 
    else: 
        remaining += count
over_100.append(("Remaining", remaining))
# over_100 = fcall_list[:100]
over_100_functions = [item[0] for item in over_100]
pickle.dump(over_100_functions, open('function_names.pkl', 'wb'))

non_remaining = sum([item[1] for item in over_100])
remaining = sum([item[1] for item in fcall_list[100:]])


for item, count in over_100:
    print(f'{item}: {count}')

print(f'len: {len(over_100)}')

print('non-remaining: ', non_remaining)
print('remaining:', remaining)
print('total: ', non_remaining + remaining)
print('coverage (counts): ', (non_remaining) / (non_remaining + remaining))
print('coverage (names): ', len(over_100) / (len(over_100) + len(fcall_list)))

total_calls = sum([item[1] for item in fcall_list])
over_100_calls = sum([count[1] for count in over_100])


with open("function-call-log.txt", "a") as f:
    for item, count in over_100:
        f.write(f'{item}: {count}\n')

total_calls = sum(function_calls.values())

counts = []
percentages = []

for count in sorted(function_calls.values()):
    counts.append(count)
    percentage = (total_calls - sum(function_calls[key] for key in function_calls if function_calls[key] <= count)) / total_calls * 100
    percentages.append(percentage)

plt.plot(counts, percentages)
plt.xlabel('Count')
plt.ylabel('Percentage of Calls')
plt.title('Distribution of Function Calls')
plt.savefig('function_counts/distribution.pdf')