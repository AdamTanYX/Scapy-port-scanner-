from scapy.all import *
import customtkinter as ctk
from tkinter import messagebox

def scan_ports():
    target = target_entry.get()
    startport = int(startport_entry.get())
    endport = int(endport_entry.get())
    output = "Scanning " + target + " for open TCP ports....\n\n"
    open_ports = []
     
     

    if startport>= 0 and endport <= 65536 : 
        endport+= 1 #the endport is included in the scanning
        output = "Opened Ports:\n"
        for x in range(startport, endport): #iterate through the ports
         packet = IP(dst=target)/TCP(dport=x, flags='S') #create a packet to the target ip with portno. x with a seg req
         response = sr1(packet, timeout=0.5, verbose=0) #send and receive the packet, verbose = 0 means no output will be printed while executing 
         if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12: #check whther there is  response and has TCP layer and theflag is SYN/ACK 
            output += str(x)+ "\n"  
         sr(IP(dst=target)/TCP(dport=x, flags='R'), timeout=0.5, verbose=0)    #end the TCP connection with RST packet 

        output += "\nScan Completed!"

    else: #if port entered is out of range 
    
        output+="Port out of range! (0-65536)"

    
    messagebox.showinfo("Port Scan Results", output)


#GUI (customtkinter)
    
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


root = ctk.CTk()
root.geometry("300x150")
root.title("Port Scanner")

target_label = ctk.CTkLabel(root, text="Target IP/Domain Name:")
target_label.grid(row=0, column=0, padx=5, pady=5)
target_entry = ctk.CTkEntry(root)
target_entry.grid(row=0, column=1, padx=5, pady=5)

startport_label = ctk.CTkLabel(root, text="Start Port:")
startport_label.grid(row=1, column=0, padx=5, pady=5)
startport_entry = ctk.CTkEntry(root)
startport_entry.grid(row=1, column=1, padx=5, pady=5)

endport_label = ctk.CTkLabel(root, text="End Port:")
endport_label.grid(row=2, column=0, padx=5, pady=5)
endport_entry = ctk.CTkEntry(root)
endport_entry.grid(row=2, column=1, padx=5, pady=5)

scan_button = ctk.CTkButton(root, text="Scan Ports", command=scan_ports)
scan_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()