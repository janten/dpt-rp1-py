'''
Created on Feb 24, 2018

@author: brian
'''

import logging, urllib3

from envisage.ui.tasks.api import PreferencesPane as _PreferencesPane
from pyface.api import error
from apptools.preferences.api import PreferencesHelper
from traits.api import Bool, Dict, Str, Unicode, Bytes, Event, HasTraits, CInt
from traitsui.api import EnumEditor, HGroup, VGroup, Item, Label, View, ButtonEditor, OKButton

from dptrp1.dptrp1 import DigitalPaper

class Preferences(PreferencesHelper):
    """ 
    The preferences helper
    """

    #### 'PreferencesHelper' interface ########################################

    # The path to the preference node that contains the preferences.
    preferences_path = 'dpt_rp1.preferences'

    addr = Str
    client_id = Str
    key = Str
    serial_number = Str("<Unregistered>")

    # The task to activate on app startup if not restoring an old layout.
    default_task = Str

    # Whether to always apply the default application-level layout.
    # See TasksApplication for more information.
    always_use_default_layout = Bool
    
#     register = Event
    
#     def _register_fired(self):

    
class PreferencesPane(_PreferencesPane):
    """ 
    The preferences pane
    """

    # The factory to use for creating the preferences model object.
    model_factory = Preferences

    view = View(Item('serial_number',
                     label = "DPT-RP1 serial number: ",
                     style = 'readonly'),
                Item('addr',
                     label = "DPT-RP1 address: "),
                Item('handler.register',
                     editor = ButtonEditor(label = "Register a new DPT-RP1"),
                     show_label = False))
    
    register = Event
    
    # MAGIC - called when `register` changes
    def _register_fired(self):
        
        try:
            http = urllib3.PoolManager()
            http.request('GET', 'https://' + self._model.addr + ':8443', retries = False)
        except urllib3.exceptions.NewConnectionError:
            error("Could not connect to DPT-RP1 at {}", 'https://' + self._model.addr + ':8443')
            return
        
        dp = DigitalPaper(addr = self._model.addr)
        _, self._model.key, self._model.client_id = dp.register(self._get_pin)
        
        dp.authenticate(self._model.client_id, self._model.key)
        self._model.serial_number = dp.device_information()['serial_number']
        
    def _get_pin(self):
        class Pin(HasTraits):
            pin = CInt
            
            view = View(Label("Please enter the PIN displayed on the DPT-RP1"),
                        Item('pin'),
                        title = "Enter PIN",
                        buttons = [OKButton],
                        close_result = False)
            
        p = Pin()
        p.edit_traits(kind = 'modal')

        logging.debug("PIN: {}".format(p.pin))
        
        return str(p.pin)
        
        
        
    # TODO - on okay, try connecting to make sure ip addr is okay
    