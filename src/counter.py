import collections


c = collections.Counter("abedihfdiwhfhdsd")
ranked_c = c.most_common()
for ele in ranked_c:
    print(ele[0])
print(sorted(c))