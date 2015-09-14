# The MIT License (MIT)
#
# Copyright (c) 2015 One Thawt one.thawt@gmail.com, https://github.com/onethawt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import idautils
import idc
from idaapi import PluginForm
import operator
import csv

from PySide import QtGui, QtCore

def dxc_get_segments():
    seg_list = []
    for seg in Segments():
        seg_list.append("%s %s" % (str(hex(seg)),SegName(seg)))
    return seg_list

def dxc_scan_refs(seg, min_refs):
    start = SegStart(seg)
    end = SegEnd(seg)

    data_refs = {}

    for ea in idautils.Heads(start, end):
        gen_xrefs = XrefsTo(ea, 0)
        for xx in gen_xrefs:
            if ea in data_refs.keys():
                data_refs[ea] = data_refs[ea] + 1
            else:
                data_refs[ea] = 1

    data_refs = sorted(data_refs.items(), key=operator.itemgetter(1))
    data_refs = filter(lambda x: x[1] >= min_refs, data_refs)

    return data_refs

class DxcFormClass(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)
        self.tableWidget = QtGui.QTableWidget()
        self.seg_combo = QtGui.QComboBox()
        self.refcount_box = QtGui.QLineEdit()
        self.export_btn = QtGui.QPushButton("Export")
        self.export_btn.setDisabled(True)
        self.scan_btn = QtGui.QPushButton("Scan")
        self.minfilter_box = QtGui.QLineEdit()
        self.maxfilter_box = QtGui.QLineEdit()
        self.filter_btn = QtGui.QPushButton("Filter")
        self.filter_btn.setDisabled(True)
        self.sort_order = [QtCore.Qt.AscendingOrder, QtCore.Qt.AscendingOrder]
        self.PopulateForm()



    def PopulateForm(self):
        vboxLayout = QtGui.QVBoxLayout()

        self.tableWidget.setRowCount(1)
        self.tableWidget.setColumnCount(2)
        self.tableWidget.setHorizontalHeaderItem(0, QtGui.QTableWidgetItem("Address"))
        self.tableWidget.setHorizontalHeaderItem(1, QtGui.QTableWidgetItem("Reference Count"))

        gridLayout = QtGui.QGridLayout()

        self.seg_combo.addItems(dxc_get_segments())
        self.seg_combo.setMaximumWidth(100)
        self.seg_combo.setFixedWidth(100)

        gridLayout.addWidget(QtGui.QLabel("Segment start:"), 0, 0)
        gridLayout.addWidget(self.seg_combo, 0, 1)

        gridLayout.addWidget(QtGui.QLabel("Minimum ref count:"), 1, 0)

        self.refcount_box.setMaximumWidth(100)
        self.refcount_box.setFixedWidth(100)
        self.refcount_box.setText("50")

        self.minfilter_box.setMaximumWidth(100)
        self.minfilter_box.setFixedWidth(100)
        self.maxfilter_box.setMaximumWidth(100)
        self.maxfilter_box.setFixedWidth(100)
        self.minfilter_box.setText("0")
        self.maxfilter_box.setText("100000")

        gridLayout.addWidget(self.export_btn, 0, 2)
        gridLayout.addWidget(self.refcount_box, 1, 1)
        gridLayout.addWidget(self.scan_btn, 1, 2)
        gridLayout.addWidget(self.minfilter_box, 2, 0)
        gridLayout.addWidget(self.maxfilter_box, 2, 1)
        gridLayout.addWidget(self.filter_btn, 2, 2)
        gridLayout.addWidget(self.tableWidget, 3, 0, 1, 5)

        self.export_btn.clicked.connect(self.OnExport)
        self.scan_btn.clicked.connect(self.OnScan)
        self.filter_btn.clicked.connect(self.OnFilter)
        self.tableWidget.cellDoubleClicked.connect(self.OnJump)
        self.tableWidget.horizontalHeader().sectionClicked.connect(self.OnSectionClicked)

        gridLayout.setColumnStretch(4, 1)
        vboxLayout.addLayout(gridLayout)

        self.parent.setLayout(vboxLayout)

    def OnClose(self, form):
        pass

    def OnScan(self):
        self.tableWidget.setRowCount(0)
        self.export_btn.setDisabled(True)
        self.filter_btn.setDisabled(True)
        self.scan_btn.setDisabled(True)
        self.scan_btn.setText("Scanning...")
        self.parent.repaint()
        seg = int(self.seg_combo.itemText(self.seg_combo.currentIndex()).split(' ')[0], 16)
        min_refs = int(self.refcount_box.text())
        refs = dxc_scan_refs(seg, min_refs)
        self.tableWidget.setRowCount(len(refs))

        for i, row in enumerate(refs):
            addr_item = QtGui.QTableWidgetItem()
            addr_item.setData(QtCore.Qt.EditRole, row[0])
            addr_item.setData(QtCore.Qt.DisplayRole, str(hex(row[0])))
            count_item = QtGui.QTableWidgetItem()
            count_item.setData(QtCore.Qt.EditRole, row[1])
            count_item.setData(QtCore.Qt.DisplayRole, str(row[1]))
            self.tableWidget.setItem(i, 0, addr_item)
            self.tableWidget.setItem(i, 1, count_item)

        self.scan_btn.setText("Scan")
        self.scan_btn.setDisabled(False)
        self.filter_btn.setDisabled(False)
        self.export_btn.setDisabled(False)

    def OnFilter(self):
        for i in range(0, self.tableWidget.rowCount()):
            item = self.tableWidget.item(i, 1)
            if (item is not None and item.data(QtCore.Qt.EditRole) > int(self.maxfilter_box.text()) or
                item.data(QtCore.Qt.EditRole) < int(self.minfilter_box.text())):
                self.tableWidget.setRowHidden(i, True)
            else:
                self.tableWidget.setRowHidden(i, False)

    def OnJump(self, row, column):
        ea = self.tableWidget.item(row, column).text()
        if column == 0:
            idc.Jump(int(ea, 16))

    def OnSectionClicked(self, sectionIndex):
        if self.sort_order[sectionIndex] == QtCore.Qt.AscendingOrder:
            self.sort_order[sectionIndex] = QtCore.Qt.DescendingOrder
            self.tableWidget.sortByColumn(sectionIndex, QtCore.Qt.DescendingOrder)
        else:
            self.sort_order[sectionIndex] = QtCore.Qt.AscendingOrder
            self.tableWidget.sortByColumn(sectionIndex, QtCore.Qt.AscendingOrder)

    def OnExport(self):
        fname, _ = QtGui.QFileDialog.getSaveFileName()
        if fname:
            with open(unicode(fname), 'wb') as ostream:
                writer = csv.writer(ostream)
                for row in range(0, self.tableWidget.rowCount()):
                    row_data = []
                    for column in range(0, self.tableWidget.columnCount()):
                        item = self.tableWidget.item(row, column)
                        if item is not None:
                            row_data.append(unicode(item.text()).encode('utf8'))
                        else:
                            row_data.append('')
                    writer.writerow(row_data)

dxcplg = DxcFormClass()
dxcplg.Show("Data XRef Counter")

