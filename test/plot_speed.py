import sys, os

import numpy
import matplotlib
import csv
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import matplotlib.cm as cm

# ---------------------------
# Handle command line args

if len(sys.argv) < 3:
  print "usage: python plot_speed.py <file> <title> [fix-scale] [colourmap]"
  sys.exit(0)

input_file = sys.argv[1]

fix_scale = 0
if len(sys.argv) > 3:
  fix_scale = int(sys.argv[3])

if len(sys.argv) > 4:
  colourmap = sys.argv[4]
else:
  colourmap = "winter"

data = map(lambda(x): (8589934592. / x) / (1024 * 1024) * (1000000000.), numpy.loadtxt(input_file))

fig = plt.figure(figsize=(4,3))

if fix_scale != 0:
  plt.matshow(data, vmax=0.000006, vmin=0.000001, fignum=0, cmap=colourmap)
else:
  plt.matshow(data, fignum=0, cmap=colourmap, origin='lower')


plt.ylabel('Core ID')
#plt.ylim(0, 48)
plt.xlabel('Core ID')
#plt.xlim(0, 48)
plt.title(sys.argv[2])

cb = plt.colorbar(shrink=1.0, format='%.3f')
cb.set_label('Speed mbits/sec')

plt.savefig(sys.argv[1] + ".png", format="png", bbox_inches='tight')

