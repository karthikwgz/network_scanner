from rich import print
from datetime import datetime
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.style import Style
from rich.console import Console
import network_scanner as ns

console = Console()

grid = Table.grid(expand=True)
grid.add_column(justify="center", ratio=1)
grid.add_column(justify="right")
grid.add_row(
    "Network Scanner Tool",
    datetime.now().ctime().replace(":", "[blink]:[/]"),
)
print(Panel(grid, style="white on blue"))

def fn_menu():
    grid1 = Table(expand=True,border_style="white")
    grid1.add_column("[purple]Choice[purple]",justify="right",style="purple")
    grid1.add_column("[purple]Details[purple]",justify="center",style="purple")
    grid1.add_row(
        "1","Scan single host"
    )
    grid1.add_row(
        "2","Scan range"
    )
    grid1.add_row(
        "3","Scan network"
    )
    grid1.add_row(
        "4","Agressive scan"
    )
    grid1.add_row(
        "5","Scan ARP packet"
    )
    grid1.add_row(
        "6","Scan all port only"
    )
    grid1.add_row(
        "7","Scan in verbose mode"
    )
    grid1.add_row(
        "8","Exit"
    )
    print(grid1)
    console.print("Enter your choice : ",style="orchid1")

def choice():
    fn_menu()
    ch = int(input())
    if ch == 1:
        ns.scan_single_host()
        choice()
    elif ch == 2:
        ns.scan_range()
        choice()
    elif ch == 3:
        ns.scan_network()
        choice()
    elif ch == 4:
        ns.aggressive_scan()
        choice()
    elif ch == 5:
        ns.arp_packet()
        choice()
    elif ch == 6:
        ns.scan_all_ports()
        choice()
    elif ch == 7:
        ns.verbose_scan()
        choice()
    elif ch == 8:
        exit()
    else:
        print("Wrong choice")
        choice()
        
choice()