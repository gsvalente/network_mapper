"""
Base Component Classes for GUI Architecture
"""
import tkinter as tk
from tkinter import ttk
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Callable


class BaseComponent(ABC):
    """Base class for all GUI components"""
    
    def __init__(self, parent: tk.Widget, controller: Optional[object] = None):
        self.parent = parent
        self.controller = controller
        self.frame = None
        self.widgets = {}
        self._setup_component()
    
    @abstractmethod
    def _setup_component(self):
        """Setup the component's UI elements"""
        pass
    
    def get_frame(self) -> tk.Frame:
        """Get the main frame of this component"""
        return self.frame
    
    def get_widget(self, name: str) -> Optional[tk.Widget]:
        """Get a specific widget by name"""
        return self.widgets.get(name)
    
    def set_controller(self, controller: object):
        """Set the controller for this component"""
        self.controller = controller


class BasePanel(BaseComponent):
    """Base class for panel components"""
    
    def __init__(self, parent: tk.Widget, title: str = "", controller: Optional[object] = None):
        self.title = title
        super().__init__(parent, controller)
    
    def _setup_component(self):
        """Setup the panel with a labeled frame"""
        self.frame = ttk.LabelFrame(self.parent, text=self.title, padding="10")
        self._create_panel_content()
    
    @abstractmethod
    def _create_panel_content(self):
        """Create the content of the panel"""
        pass


class BaseTab(BaseComponent):
    """Base class for tab components"""
    
    def __init__(self, parent: ttk.Notebook, tab_name: str, controller: Optional[object] = None):
        self.tab_name = tab_name
        super().__init__(parent, controller)
        parent.add(self.frame, text=tab_name)
    
    def _setup_component(self):
        """Setup the tab frame"""
        self.frame = ttk.Frame(self.parent)
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(0, weight=1)
        self._create_tab_content()
    
    @abstractmethod
    def _create_tab_content(self):
        """Create the content of the tab"""
        pass


class EventMixin:
    """Mixin class for event handling"""
    
    def __init__(self):
        self._event_handlers = {}
    
    def bind_event(self, event_name: str, handler: Callable):
        """Bind an event handler"""
        if event_name not in self._event_handlers:
            self._event_handlers[event_name] = []
        self._event_handlers[event_name].append(handler)
    
    def trigger_event(self, event_name: str, *args, **kwargs):
        """Trigger an event"""
        if event_name in self._event_handlers:
            for handler in self._event_handlers[event_name]:
                handler(*args, **kwargs)
    
    def unbind_event(self, event_name: str, handler: Callable = None):
        """Unbind event handlers"""
        if event_name in self._event_handlers:
            if handler:
                self._event_handlers[event_name].remove(handler)
            else:
                self._event_handlers[event_name].clear()


class ValidatedEntry(ttk.Entry):
    """Entry widget with validation support"""
    
    def __init__(self, parent, validator: Optional[Callable] = None, **kwargs):
        super().__init__(parent, **kwargs)
        self.validator = validator
        self._setup_validation()
    
    def _setup_validation(self):
        """Setup validation for the entry"""
        if self.validator:
            vcmd = (self.register(self._validate), '%P')
            self.config(validate='key', validatecommand=vcmd)
    
    def _validate(self, value: str) -> bool:
        """Validate the entry value"""
        if self.validator:
            return self.validator(value)
        return True
    
    def get_validated_value(self):
        """Get the value if it's valid, otherwise return None"""
        value = self.get()
        if self.validator and not self.validator(value):
            return None
        return value