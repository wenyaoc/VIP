from operator import itemgetter
import collections

d = {
    "alice": 1,
    "bob": 5,
    "trudy": 3
}

k = collections.Counter(d)
sorted_k = k.most_common()

for entry in sorted_k:
    print(entry[0])

"""
sorted_keys = sorted(d.items(), key=itemgetter(1), reverse=True) 


for key, val in sorted_keys:
    print "%s: %d" % (key, val)
"""