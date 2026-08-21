# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
from tkinter import ttk

from env_config import load_project_env_once

load_project_env_once()

# Install the runtime-isolated Go backend spawn policy before the dashboard
# imports and constructs backend instances.
from runtime_backend_patch import install_runtime_backend_hardening

install_runtime_backend_hardening()

# UI-only branch: keep the existing runtime/backend and launch the modern skin.
from dashboard_modern_ui import SmartCarDashboard


def main():
    app = SmartCarDashboard()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)

    style = ttk.Style()
    style.theme_use('clam')
    style.configure(
        "Horizontal.TProgressbar",
        background='#24d18b',
        troughcolor='#07121e',
        bordercolor='#1c3048'
    )
    for name in ["FUEL", "THROTTLE", "BRAKE", "BATTERY"]:
        colors = {
            'FUEL': '#24d18b',
            'THROTTLE': '#f59e0b',
            'BRAKE': '#ff5c6c',
            'BATTERY': '#4f7cff'
        }
        style.configure(
            f"{name}.Horizontal.TProgressbar",
            background=colors.get(name, '#4f7cff'),
            troughcolor='#07121e'
        )

    app.mainloop()


if __name__ == "__main__":
    main()
