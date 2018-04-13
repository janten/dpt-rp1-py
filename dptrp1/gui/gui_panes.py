'''
Created on Feb 24, 2018

@author: brian
'''

from pyface.tasks.api import TaskPane
from traits.api import Instance

from dptrp1.gui.dpt_model import DPTModel

class DPTPane(TaskPane):
    """ A wrapper around the Pyface Python editor.
    """

    id = 'dpt_rp1.dpt_pane'
    name = 'DPT-RP1 contents'

    model = Instance(DPTModel)

    def create(self, parent):
        self.control = self.model.edit_traits(kind = 'subpanel', 
                                              parent = parent,
                                              handler = self.task).control

    def destroy(self):
        self.control = None