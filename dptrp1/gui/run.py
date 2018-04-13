'''
Created on Feb 24, 2018

@author: brian
'''

import logging, os, pickle, threading, traceback, sys

from envisage.ui.tasks.api import TasksApplication
from envisage.ui.tasks.tasks_application import TasksApplicationState
from pyface.api import error
from pyface.tasks.api import TaskWindowLayout
from traits.api import Bool, Instance, List, Property, Str

logger = logging.getLogger(__name__)

from dptrp1.gui.preferences import Preferences

def log_notification_handler(_, trait_name, old, new):
    
    (exc_type, exc_value, tb) = sys.exc_info()
    logging.debug('Exception occurred in traits notification '
                  'handler for object: %s, trait: %s, old value: %s, '
                  'new value: %s.\n%s\n' % ( object, trait_name, old, new,
                  ''.join( traceback.format_exception(exc_type, exc_value, tb) ) ) )

    err_string = traceback.format_exception_only(exc_type, exc_value)[0]
    err_loc = traceback.format_tb(tb)[-1]
    err_ctx = threading.current_thread().name
    
    logging.error("Error: {0}\nLocation: {1}Thread: {2}" \
                  .format(err_string, err_loc, err_ctx) )
    
def log_excepthook(typ, val, tb):
    tb_str = "".join(traceback.format_tb(tb))
    logging.debug("Global exception: {0}\n{1}: {2}"
                  .format(tb_str, typ, val))
    
    tb_str = traceback.format_tb(tb)[-1]
    logging.error("Error: {0}: {1}\nLocation: {2}Thread: Main"
                  .format(typ, val, tb_str))


def gui_handler_callback(msg, app):
    app.application_error = msg
    

class CallbackHandler(logging.Handler):
    def __init__(self, callback):
        logging.Handler.__init__(self)
        self._callback = callback
        
    def emit(self, record):
        self._callback(record.getMessage())


class DPTApplication(TasksApplication):

    # The application's globally unique identifier.
    id = 'dptrp1.app'

    # The application's user-visible name.
    name = 'DPT-RP1 Manager'

    # The default window-level layout for the application.
    default_layout = List(TaskWindowLayout)
 
    # if there's an ERROR-level log message, drop it here     
    application_error = Str
 
    # Whether to restore the previous application-level layout when the
    # applicaton is started.
    always_use_default_layout = Property(Bool)

    preferences_helper = Instance(Preferences)

    def _default_layout_default(self):
        active_task = self.preferences_helper.default_task
        tasks = [ factory.id for factory in self.task_factories ]
        return [ TaskWindowLayout(*tasks,
                                  active_task = active_task,
                                  size = (800, 600)) ]

    def _preferences_helper_default(self):
        return Preferences(preferences = self.preferences)

    def _get_always_use_default_layout(self):
        return self.preferences_helper.always_use_default_layout
    
    def show_error(self, error_string):
        error(None, error_string)
        
    def _load_state(self):
        """ 
        Loads saved application state, if possible.  Overload the envisage-
        defined one to fix a py3k bug and increment the TasksApplicationState
        version.
        
        """
        state = TasksApplicationState(version = 2)
        filename = os.path.join(self.state_location, 'application_memento')
        if os.path.exists(filename):
            # Attempt to unpickle the saved application state.
            try:
                with open(filename, 'rb') as f:
                    restored_state = pickle.load(f)
                if state.version == restored_state.version:
                    state = restored_state
                else:
                    logger.warn('Discarding outdated application layout')
            except:
                # If anything goes wrong, log the error and continue.
                logger.exception('Had a problem restoring application layout from %s',
                                 filename)
                 
        self._state = state

    def _save_state(self):
        """
        Saves the application state -- ONLY IF THE CYTOFLOW TASK IS ACTIVE
        
        """

        # Grab the current window layouts.
        window_layouts = [w.get_window_layout() for w in self.windows]
        self._state.previous_window_layouts = window_layouts
     
        # Attempt to pickle the application state.
        filename = os.path.join(self.state_location, 'application_memento')
        try:
            with open(filename, 'wb') as f:
                pickle.dump(self._state, f)
        except:
            # If anything goes wrong, log the error and continue.
            logger.exception('Had a problem saving application layout')



def main(argv):
    
    logging.getLogger().setLevel(logging.DEBUG)
    
    ## send the log to STDERR
    try:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s:%(name)s:%(message)s"))
        logging.getLogger().addHandler(console_handler)
    except:
        # if there's no console, this fails
        pass
 
    # install a global (gui) error handler for traits notifications
    from traits.api import push_exception_handler
    push_exception_handler(handler = log_notification_handler,
                           reraise_exceptions = True, 
                           main = True)
    

    from envisage.core_plugin import CorePlugin
    from envisage.ui.tasks.tasks_plugin import TasksPlugin
    from dptrp1.gui.gui_task import GUITaskPlugin
    
    app = DPTApplication(plugins = [CorePlugin(), TasksPlugin(), GUITaskPlugin()])
    
    ## and display gui messages for exceprions
    gui_handler = CallbackHandler( lambda msg, app = app: gui_handler_callback(msg, app))
    gui_handler.setLevel(logging.ERROR)
    logging.getLogger().addHandler(gui_handler)  
    
    # must redirect to the gui thread
    app.on_trait_change(app.show_error, 'application_error', dispatch = 'ui')

    sys.excepthook = log_excepthook    

    def _size_hint_wrapper(f, ui):
        """Wrap an existing sizeHint method with sizes from a UI object.
        """
        def sizeHint():
            size = f()
            if ui.view is not None and ui.view.width > 0:
                size.setWidth(ui.view.width)
            if ui.view is not None and ui.view.height > 0:
                size.setHeight(ui.view.height)
            return size
        return sizeHint
    
    import traitsui.qt4.ui_panel
    traitsui.qt4.ui_panel._size_hint_wrapper = _size_hint_wrapper

    def _tree_hash(self):
        return id(self)
    
    def _tree_eq(self, other):
        return id(self) == id(other)
    
    from PyQt4.QtGui import QTreeWidgetItem
    QTreeWidgetItem.__hash__ = _tree_hash
    QTreeWidgetItem.__eq__ = _tree_eq
    
    app.run()

if __name__ == '__main__':
    import sys
    main(sys.argv)
