# idapyscripts
### Collection of my IDAPython scripts
* **Data Xref Counter** (dataxrefcounter.py) - A small IDAPython plugin which enumerates all of the the x-references in a specific segment and counts the frequency of usage. The plugin displays the data in QtTableWidget and lets the user filter and sort the references. You can also export the data to a CSV file. This plugin is particularly useful when reverse engineering large executables (games). In the video below, I demonstrate the plugin on an IDA database of Diablo 3 (patch 2.3). The second most referenced data offset happens to be the ObjectManager, which contains many of the interesting game data values and pointers to other structures.


[![Data Xref Counter](http://img.youtube.com/vi/r_lbYsU3jSU/0.jpg)](http://www.youtube.com/watch?v=r_lbYsU3jSU)
