# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
from tkinter import ttk

from env_config import load_project_env_once

load_project_env_once()

from dashboard import SmartCarDashboard


def main():
    app = SmartCarDashboard()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)

    style = ttk.Style()
    style.theme_use('clam')
    style.configure(
        "Horizontal.TProgressbar",
        background='#10b981',
        troughcolor='#111827',
        bordercolor='#1f3a5f'
    )
    for name in ["FUEL", "THROTTLE", "BRAKE", "BATTERY"]:
        colors = {
            'FUEL': '#10b981',
            'THROTTLE': '#f59e0b',
            'BRAKE': '#ef4444',
            'BATTERY': '#00d4ff'
        }
        style.configure(
            f"{name}.Horizontal.TProgressbar",
            background=colors.get(name, '#00d4ff'),
            troughcolor='#111827'
        )

    app.mainloop()


if __name__ == "__main__":
    main()

