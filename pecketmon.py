#!/usr/bin/python3

"""
This program was originally created by Isaac Privett on 03-16-2023
Feel free to use it as you wish
"""

import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
from scapy.all import sniff, IP, TCP, UDP
from ctypes import c_char_p, c_int, create_string_buffer
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from collections import defaultdict
import os


class Alert:
	def __init__(self, name, condition, message):
		self.name = name
		self.condition = condition
		self.message = message

	def check(self, packet, counters):
		if self.condition(packet, counters):
			return self.message
		return None


class NetworkMonitor:
	def __init__(self, root, filter):
		self.root = root
		self.filter = filter
		self.packet_queue = []
		self.packet_count = 0
		self.prev_packet_count = 0
		self.packets_per_second = 0
		self.chart_data = [0] * 60
		self.log_filename = "packet_log.txt"
		self.src_port_count = defaultdict(set)
		if os.path.exists(self.log_filename):
			os.remove(self.log_filename)
		self.alerts = [
			Alert("Example Alert", lambda packet, counters: packet[IP].src == "8.8.8.8", "Detected a packet from 8.8.8.8"),
			Alert("Port Scan Alert", lambda packet, counters: self.port_scan_condition(packet, {"src_port_count": self.src_port_count}), "Possible port scan detected")
		]
		self.ip_packet_count = defaultdict(int)
		self.outbound_packet_count = defaultdict(int)
		self.outbound_connections = defaultdict(int)
		self.inbound_connections = defaultdict(int)

		self.build_gui()

	def build_gui(self):
		self.root.title("Network Monitor")
		self.root.geometry("1000x500")
		self.build_menu()
		main_frame = tk.Frame(self.root)
		main_frame.pack(fill=tk.BOTH, expand=True)
		
		name_label = tk.Label(main_frame, text="Isaac's Basic Network Monitor", font=("Helvetica", 20))
		name_label.grid(row=0, column=0, padx=10, pady=5)

		self.packet_display = ScrolledText(main_frame, wrap=tk.WORD, height=20, width=40)
		self.packet_display.grid(row=1, column=0, rowspan=4, padx=10, pady=10)

		start_button = ttk.Button(main_frame, text="Start", command=self.start_sniffing)
		start_button.grid(row=5, column=0, padx=10, pady=10)


		log_button = tk.Button(main_frame, text="View Log", command=self.view_log)
		log_button.grid(row=5, column=1, padx=10, pady=10)
		

		self.figure = Figure(figsize=(6, 4), dpi=100)
		self.line_chart = self.figure.add_subplot(1, 1, 1)
		self.line, = self.line_chart.plot(self.chart_data)
		self.line_chart.set_title("Packets Per Second")
		self.line_chart.set_xlabel("Time (s)")
		self.line_chart.set_ylabel("Packet Count")
		self.line_chart.set_ylim(0, max(self.chart_data) + 1)
		self.line_chart.set_xlim(0, len(self.chart_data) - 1)

		self.canvas = FigureCanvasTkAgg(self.figure, master=main_frame)
		self.canvas.get_tk_widget().grid(row=1, column=1, rowspan=4, padx=10, pady=10)
		
		ip_packet_count_label = tk.Label(main_frame, text="Incoming Packets Count (IP: Count)")
		ip_packet_count_label.grid(row=6, column=0, padx=10, pady=5)
		
		self.ip_packet_count_display = ScrolledText(main_frame, wrap=tk.WORD, height=10, width=40)
		self.ip_packet_count_display.grid(row=7, column=0, padx=10, pady=10)
		
		
		outbound_packet_count_label = tk.Label(main_frame, text="Outbound Packets Count (IP: Count)")
		outbound_packet_count_label.grid(row=6, column=1, padx=10, pady=5)
	
		self.outbound_packet_count_display = ScrolledText(main_frame, wrap=tk.WORD, height=10, width=40)
		self.outbound_packet_count_display.grid(row=7, column=1, padx=10, pady=10)
		
		# Add a new ScrolledText widget to display the alerts
		alert_label = tk.Label(main_frame, text="Alerts")
		alert_label.grid(row=0, column=2, padx=10, pady=5)
		self.alert_display = ScrolledText(main_frame, wrap=tk.WORD, height=20, width=40)
		self.alert_display.grid(row=1, column=2, rowspan=4, padx=10, pady=10)
		

		self.update_chart_auto()

	def start_sniffing(self):
		sniff_thread = threading.Thread(target=self.sniff_packets, args=(self.filter,))
		sniff_thread.daemon = True
		sniff_thread.start()

	def sniff_packets(self, filter):
		sniff(prn=self.process_packet, filter=filter, store=False)

	def process_packet(self, packet):
		if packet.haslayer(IP):
			transport_layer = packet[UDP] if packet.haslayer(UDP) else packet[TCP]
			packet_info = f"Source IP: {packet[IP].src}:{transport_layer.sport} -> Destination IP: {packet[IP].dst}:{transport_layer.dport}\n"
			packet_content = f"{packet.summary()}\n{packet.show(dump=True)}\n{'*' * 50}\n"

			self.packet_queue.append((packet_info, packet_content))
			self.packet_count += 1
			self.ip_packet_count[packet[IP].src] += 1
			self.outbound_packet_count[packet[IP].dst] += 1
			self.write_to_log_file(packet_info, packet_content)
			self.src_port_count[packet[IP].src].add(transport_layer.dport)
			
			alert_message = self.check_alerts(packet)
			if alert_message:
				self.handle_alert(alert_message)
			
	def update_packet_display(self):
		while self.packet_queue:
			packet_info, packet_content = self.packet_queue.pop(0)
			self.packet_display.insert(tk.END, packet_info)
			self.packet_display.see(tk.END)
			
	def update_connection_display(self):
		self.outbound_display.delete(1.0, tk.END)
		self.inbound_display.delete(1.0, tk.END)

		for ip, count in sorted(self.outbound_connections.items(), key=lambda x: x[0]):
			self.outbound_display.insert(tk.END, f"{ip}: {count}\n")

		for ip, count in sorted(self.inbound_connections.items(), key=lambda x: x[0]):
			self.inbound_display.insert(tk.END, f"{ip}: {count}\n")

	def update_chart_auto(self):
		self.update_packet_display()
		self.update_chart()
		self.update_ip_packet_count_display()
		self.update_outbound_packet_count_display()
		self.root.after(1000, self.update_chart_auto)

	def update_chart(self):
		self.packets_per_second = self.packet_count - self.prev_packet_count
		self.prev_packet_count = self.packet_count
		self.chart_data.pop(0)
		self.chart_data.append(self.packets_per_second)

		self.line.set_ydata(self.chart_data)
		self.line_chart.set_ylim(0, max(self.chart_data) + 1)
		self.line_chart.set_xlim(0, len(self.chart_data) - 1)
		self.canvas.draw()

	def view_log(self):
		log_window = tk.Toplevel(self.root)
		log_window.title("Packet Log")
		log_window.geometry("800x600")

		log_display = ScrolledText(log_window, wrap=tk.WORD)
		log_display.pack(fill=tk.BOTH, expand=True)

		if os.path.exists(self.log_filename):
			with open(self.log_filename, "r") as log_file:
				log_display.insert(tk.END, log_file.read())

		log_window.mainloop()
		
		
	def build_menu(self):
		menu_bar = tk.Menu(self.root)
		# File menu
		file_menu = tk.Menu(menu_bar, tearoff=0)
		file_menu.add_command(label="Open Log", command=self.view_log)
		file_menu.add_separator()
		file_menu.add_command(label="Exit", command=self.root.quit)
		menu_bar.add_cascade(label="File", menu=file_menu)
		# Set the menu bar
		self.root.config(menu=menu_bar)
		
	def update_ip_packet_count_display(self):
		self.ip_packet_count_display.delete(1.0, tk.END)
		for ip, count in sorted(self.ip_packet_count.items(), key=lambda x: x[0]):
			self.ip_packet_count_display.insert(tk.END, f"{ip}: {count}\n")
			
			
	def update_outbound_packet_count_display(self):
		self.outbound_packet_count_display.delete(1.0, tk.END)
		for ip, count in sorted(self.outbound_packet_count.items(), key=lambda x: x[0]):
			self.outbound_packet_count_display.insert(tk.END, f"{ip}: {count}\n")
			
	def write_to_log_file(self, packet_info, packet_content):
		with open(self.log_filename, "a") as log_file:
			log_file.write(packet_info + packet_content)
			
	def check_alerts(self, packet):
		for alert in self.alerts:
			alert_message = alert.check(packet, {
				"ip_packet_count": self.ip_packet_count,
				"outbound_packet_count": self.outbound_packet_count,
				"inbound_connections": self.inbound_connections,
				"outbound_connections": self.outbound_connections
			})
			if alert_message:
				return alert_message
		return None
		
	def handle_alert(self, alert_message):
		self.alert_display.insert(tk.END, f"{alert_message}\n")
		self.alert_display.see(tk.END)
		
	def port_scan_condition(self, packet, counters):
		threshold = 100  # Set the threshold value
		src_ip = packet[IP].src
		unique_ports = counters["src_port_count"][src_ip]
		return len(unique_ports) > threshold
			
		
def main():
	root = tk.Tk()
	filter = "ip"
	network_monitor = NetworkMonitor(root, filter)
	root.mainloop()

if __name__ == "__main__":
	main()
