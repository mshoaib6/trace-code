import pickle
import numpy

lengths = []
for i in range(11):
    with open(f'python-filenames/lengths/pfa-{i}-length.pkl', 'rb') as f:
        array = pickle.load(f)
        lengths += array

print('pre-0 removal')
print('mean: ', numpy.mean(lengths))
print('median: ', numpy.median(lengths))
print('std dev: ', numpy.std(lengths))
print('min: ', numpy.min(lengths))
print('max: ', numpy.max(lengths))
print('percent greater than 1: ', numpy.sum([l > 1 for l in lengths])/len(lengths))

nonzero = [l for l in lengths if l > 0]

print('\n\npost-0 removal')
print('mean: ', numpy.mean(nonzero))
print('median: ', numpy.median(nonzero))
print('std dev: ', numpy.std(nonzero))
print('min: ', numpy.min(nonzero))
print('max: ', numpy.max(nonzero))
print('percent greater than 1: ', numpy.sum([l > 1 for l in nonzero])/len(nonzero))
