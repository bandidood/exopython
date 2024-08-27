import os
import socket
import ssl
import tkinter as tk
from collections import Counter
from datetime import datetime
from tkinter import ttk, filedialog, messagebox
import logging
# logging.basicConfig
logging.basicConfig(filename='journal.log', encoding='utf-8' , level=logging.DEBUG, format='%(asctime)s - %(levelname)s -%(message)s')

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
class CyberSecurityApp(tk.Tk):
    historiques = []

    def __init__(self):
        super().__init__()
        self.verification_log_text = None
        self.title("Cyber Security Projects")
        self.geometry("800x600")

        self.create_menu()
        self.tabControl = ttk.Notebook(self)
        self.create_tabs()
        self.tabControl.pack(expand=1, fill="both")


    def create_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # Menu Fichier
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Ouvrir", command=self.open_file)
        file_menu.add_command(label="Sauvegarder", command=self.save_file)
        file_menu.add_separator()
        #file_connexion_command(label="Login...", command=self.info)
        file_menu.add_command(label="Quitter", command=self.quit)

        # Menu Paramètres
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Préférences", command=self.show_preferences)

        # Menu Aide
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="À propos", command=self.show_about)

        # Ajout des menus à la barre de menu
        menubar.add_cascade(label="Fichier", menu=file_menu)
        menubar.add_cascade(label="Paramètres", menu=settings_menu)
        menubar.add_cascade(label="Aide", menu=help_menu)

    def open_file(self):
        messagebox.showinfo("Ouvrir", "Fonction pour ouvrir un fichier")

    def save_file(self):
        messagebox.showinfo("Sauvegarder", "Fonction pour sauvegarder un fichier")

    def show_preferences(self):
        messagebox.showinfo("Préférences", "Fonction pour montrer les préférences")

    def show_about(self):
        messagebox.showinfo("À propos", "Informations sur l'application")

    def create_tabs(self):
        self.tabs = {
            "Analyse de Logs": self.analyse_logs_tab,
            "Scanner de Ports": self.scanner_ports_tab,
            "Surveillance de Fichiers": self.surveillance_fichiers_tab,
            "Détection de Phishing": self.detection_phishing_tab,
            "Outil Bruteforce": self.outil_bruteforce_tab,
            "Vérification SSL": self.verification_ssl_tab,
            "Classement Extensions": self.classement_extensions_tab,
            "Historique": self.historique_tab,
        }

        for name, method in self.tabs.items():
            tab = ttk.Frame(self.tabControl)
            self.tabControl.add(tab, text=name)
            method(tab)

    def analyse_logs_tab(self, tab):
        ttk.Label(tab, text="Importer un fichier de logs (CSV)").grid(column=0, row=0, padx=10, pady=10)
        self.log_file_path = tk.StringVar()
        ttk.Entry(tab, textvariable=self.log_file_path, width=50).grid(column=1, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Parcourir", command=self.browse_log_file).grid(column=2, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Analyser", command=self.analyse_logs).grid(column=1, row=1, padx=10, pady=10)
        self.analyse_log_text = tk.Text(tab, width=80, height=20)
        self.analyse_log_text.grid(column=0, row=2, columnspan=3, padx=10, pady=10)
        activite = {}
        activite["date"] = datetime.now()
        activite["action"] = "Analyse de log"
        activite[("precedent")] = "..."
        activite["statut"] = "..."
        self.historiques.append(activite)

    def browse_log_file(self):
        self.log_file_path.set(filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")]))

    def analyse_logs(self):
        if not self.log_file_path.get():
            messagebox.showwarning("Attention", "Veuillez sélectionner un fichier de logs.")
            return

        logs_df = pd.read_csv(self.log_file_path.get())
        tentatives_connexion_echouees = logs_df[logs_df['EventID'] == 4625]

        fig, ax = plt.subplots(figsize=(12, 6))
        sns.countplot(data=logs_df, x='EventID', ax=ax)
        ax.set_title('Fréquence des Types d\'Événements')
        ax.set_xlabel('EventID')
        ax.set_ylabel('Nombre d\'Événements')

        plt.show()

    def scanner_ports_tab(self, tab):
        ttk.Label(tab, text="Adresse IP").grid(column=0, row=0, padx=10, pady=10)
        self.ip_address = tk.StringVar()
        ttk.Entry(tab, textvariable=self.ip_address, width=20).grid(column=1, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Scanner", command=self.scan_ports).grid(column=1, row=1, padx=10, pady=10)
        self.log_text = tk.Text(tab, width=80, height=20)
        self.log_text.grid(column=0, row=2, columnspan=3, padx=10, pady=10)
        activite = {}
        activite["date"] = datetime.now()
        activite["action"] = "Scanner port"
        activite[("precedent")] = "..."
        activite["statut"] = "..."
        self.historiques.append(activite)
    def scan_ports(self):
        if not self.ip_address.get():
            messagebox.showwarning("Attention", "Veuillez entrer une adresse IP.")
            return

        open_ports = []
        for port in range(1, 1025):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.ip_address.get(), port))
                if result == 0:
                    open_ports.append(port)

        fig, ax = plt.subplots(figsize=(12, 6))
        ax.bar(range(len(open_ports)), open_ports, color='blue')
        ax.set_title('Ports Ouverts')
        ax.set_xlabel('Index')
        ax.set_ylabel('Numéro de Port')

        plt.show()

    def surveillance_fichiers_tab(self, tab):
        ttk.Label(tab, text="Répertoire à surveiller").grid(column=0, row=0, padx=10, pady=10)
        self.directory_path = tk.StringVar()
        ttk.Entry(tab, textvariable=self.directory_path, width=50).grid(column=1, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Parcourir", command=self.browse_directory).grid(column=2, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Surveiller", command=self.monitor_directory).grid(column=1, row=1, padx=10, pady=10)
        self.log_text = tk.Text(tab, width=80, height=20)
        self.log_text.grid(column=0, row=2, columnspan=3, padx=10, pady=10)
        activite = {}
        activite["date"] = datetime.now()
        activite["action"] = "Test Phissing"
        activite[("precedent")] = "..."
        activite["statut"] = "..."
        self.historiques.append(activite)
    def browse_directory(self):
        self.directory_path.set(filedialog.askdirectory())

    def monitor_directory(self):
        if not self.directory_path.get():
            messagebox.showwarning("Attention", "Veuillez sélectionner un répertoire.")
            return

        event_handler = FileSystemEventHandler()
        event_handler.on_modified = self.on_file_modified

        observer = Observer()
        observer.schedule(event_handler, self.directory_path.get(), recursive=True)
        observer.start()
        messagebox.showinfo("Information", "Surveillance commencée.")

    def on_file_modified(self, event):
        self.log_text.insert(tk.END, f"Fichier modifié: {event.src_path}\n")
        self.log_text.see(tk.END)

    def detection_phishing_tab(self, tab):
        ttk.Label(tab, text="Dossier contenant les emails").grid(column=0, row=0, padx=10, pady=10)
        self.email_directory_path = tk.StringVar()
        ttk.Entry(tab, textvariable=self.email_directory_path, width=50).grid(column=1, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Parcourir", command=self.browse_email_directory).grid(column=2, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Analyser", command=self.analyse_emails).grid(column=1, row=1, padx=10, pady=10)
        self.email_log_text = tk.Text(tab, width=80, height=20)
        self.email_log_text.grid(column=0, row=2, columnspan=3, padx=10, pady=10)

    def browse_email_directory(self):
        self.email_directory_path.set(filedialog.askdirectory())

    def analyse_emails(self):
        if not self.email_directory_path.get():
            messagebox.showwarning("Attention", "Veuillez sélectionner un dossier d'emails.")
            return

        # Analyser les emails et détecter les tentatives de phishing
        self.email_log_text.insert(tk.END, "Analyse des emails commencée...\n")
        self.email_log_text.see(tk.END)

        # ... (Code d'analyse des emails)

        self.email_log_text.insert(tk.END, "Analyse des emails terminée.\n")
        self.email_log_text.see(tk.END)

    def outil_bruteforce_tab(self, tab):
        ttk.Label(tab, text="Service simulé (Mot de passe)").grid(column=0, row=0, padx=10, pady=10)
        self.simulated_password = tk.StringVar()
        ttk.Entry(tab, textvariable=self.simulated_password, width=20).grid(column=1, row=0, padx=10, pady=10)
        ttk.Label(tab, text="Chemin du fichier de dictionnaire").grid(column=0, row=1, padx=10, pady=10)
        self.dictionary_path = tk.StringVar()
        ttk.Entry(tab, textvariable=self.dictionary_path, width=50).grid(column=1, row=1, padx=10, pady=10)
        ttk.Button(tab, text="Parcourir", command=self.browse_dictionary).grid(column=2, row=1, padx=10, pady=10)
        ttk.Button(tab, text="Lancer l'attaque", command=self.bruteforce_attack).grid(column=1, row=2, padx=10, pady=10)
        self.bruteforce_log_text = tk.Text(tab, width=80, height=20)
        self.bruteforce_log_text.grid(column=0, row=3, columnspan=3, padx=10, pady=10)
        activite = {}
        activite["date"] = datetime.now()
        activite["action"] = "Test brute force"
        activite[("precedent")] = "..."
        activite["statut"] = "..."
        self.historiques.append(activite)
    def browse_dictionary(self):
        self.dictionary_path.set(filedialog.askopenfilename(filetypes=[("Text files", "*.txt")]))

    def bruteforce_attack(self):
        if not self.simulated_password.get() or not self.dictionary_path.get():
            messagebox.showwarning("Attention",
                                   "Veuillez entrer un mot de passe et sélectionner un fichier de dictionnaire.")
            return

        self.bruteforce_log_text.insert(tk.END, "Attaque par force brute commencée...\n")
        self.bruteforce_log_text.see(tk.END)

        with open(self.dictionary_path.get(), 'r') as file:
            for line in file:
                attempt = line.strip()
                if attempt == self.simulated_password.get():
                    self.bruteforce_log_text.insert(tk.END, f"Mot de passe trouvé: {attempt}\n")
                    self.bruteforce_log_text.see(tk.END)
                    break
            else:
                self.bruteforce_log_text.insert(tk.END, "Mot de passe non trouvé.\n")
                self.bruteforce_log_text.see(tk.END)

    def verification_ssl_tab(self, tab):
        ttk.Label(tab, text="Liste des sites web (séparés par des virgules)").grid(column=0, row=0, padx=10, pady=10)
        self.sites_web = tk.StringVar()
        ttk.Entry(tab, textvariable=self.sites_web, width=50).grid(column=1, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Vérifier", command=self.verify_ssl).grid(column=1, row=1, padx=10, pady=10)
        #ttk.Label(tab, text="Résutat de l'analyse").grid(column=0, row=20, padx=10, pady=10)
        self.verification_log = tk.Text(tab, width=80, height=20)
        self.verification_log.grid(column=0, row=2, columnspan=3, padx=10, pady=10)
        activite = {}
        activite["date"] = datetime.now()
        activite["action"] = "Vérification ssl"
        activite[("precedent")] = "..."
        activite["statut"] = "..."
        self.historiques.append(activite)
        #    "date": "",
         #   "action": "",
          #  "precedente": "date precedente",
           # "statut": "okay"
        #}

    def verify_ssl(self):
        sites = [site.strip() for site in self.sites_web.get().split(',')]
        resultats = {'valide': [], 'expire': []}
        maintenant = datetime.utcnow()
       # self.verification_log = tk.Text(tab, width=80, height=20)
        #self.verification_log.grid(column=0, row=2, columnspan=3, padx=10, pady=10)
        for site in sites:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((site, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=site) as ssock:
                        cert = ssock.getpeercert()
                        date_expiration = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if date_expiration < maintenant:
                            resultats['expire'].append(site)
                        else:
                            resultats['valide'].append(site)
            except Exception as e:
                #messagebox.showwarning("Erreur", f"Erreur pour {site}: {e}")
                resultats['expire'].append(site)  # Considérer les erreurs comme expirées

        #resultat_label
        resultat_text = ("Certificats SSL validées :\n" + "\n".join(resultats["valide"]) + "\n\n")
        resultat_text += ("Certificats SSL expirés ou avec erreur :\n" + "\n".join(resultats["expire"]))

        self.verification_log.delete(1.0, tk.END)
        self.verification_log.insert(tk.END, resultat_text)
        self.verification_log.see(tk.END)

        plt.show()

    def classement_extensions_tab(self, tab):
        ttk.Label(tab, text="Répertoire à analyser").grid(column=0, row=0, padx=10, pady=10)
        self.extension_directory_path = tk.StringVar()
        ttk.Entry(tab, textvariable=self.extension_directory_path, width=50).grid(column=1, row=0, padx=10, pady=10)
        ttk.Button(tab, text="Parcourir", command=self.browse_extension_directory).grid(column=2, row=0, padx=10,
                                                                                        pady=10)
        ttk.Button(tab, text="Analyser", command=self.analyse_extensions).grid(column=1, row=1, padx=10, pady=10)
        ttk.Button(tab, text="Classer", command=self.classer_fichiers).grid(column=2, row=1, padx=10, pady=10)
        self.extension_log_text = tk.Text(tab, width=80, height=20)
        self.extension_log_text.grid(column=0, row=2, columnspan=3, padx=10, pady=10)
        activite = {}
        activite["date"] = datetime.now()
        activite["action"] = "Tri extension"
        activite[("precedent")] = "..."
        activite["statut"] = "..."
        self.historiques.append(activite)

    def browse_extension_directory(self):
        self.extension_directory_path.set(filedialog.askdirectory())

    def analyse_extensions(self):
        if not self.extension_directory_path.get():
            messagebox.showwarning("Attention", "Veuillez sélectionner un répertoire.")
            return

        self.extensions_counter = Counter()
        for root, _, files in os.walk(self.extension_directory_path.get()):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                self.extensions_counter[ext] += 1

        extensions, counts = zip(*self.extensions_counter.items())

        fig, ax = plt.subplots(figsize=(12, 6))
        ax.bar(extensions, counts, color='blue')
        ax.set_title('Classement des Extensions de Fichier')
        ax.set_xlabel('Extension')
        ax.set_ylabel('Nombre de Fichiers')

        plt.show()

    def classer_fichiers(self):
        if not self.extension_directory_path.get():
            messagebox.showwarning("Attention", "Veuillez sélectionner un répertoire.")
            return

        log_entries = []
        total_files = 0
        successful_moves = 0
        failed_moves = 0

        for ext in self.extensions_counter:
            ext_dir = os.path.join(self.extension_directory_path.get(), ext[1:] if ext else "sans_extension")
            if not os.path.exists(ext_dir):
                os.makedirs(ext_dir)

        for root, _, files in os.walk(self.extension_directory_path.get()):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                src_path = os.path.join(root, file)
                dest_dir = os.path.join(self.extension_directory_path.get(), ext[1:] if ext else "sans_extension")
                dest_path = os.path.join(dest_dir, file)

                try:
                    os.rename(src_path, dest_path)
                    log_entries.append(f"Réussi: {src_path} -> {dest_path}")
                    successful_moves += 1
                except Exception as e:
                    log_entries.append(f"Échec: {src_path} -> {dest_path} ({e})")
                    failed_moves += 1

                total_files += 1

        log_entries.append(f"\nTotal de fichiers traités: {total_files}")
        log_entries.append(f"Réussites: {successful_moves}")
        log_entries.append(f"Échecs: {failed_moves}")

        log_file_path = os.path.join(self.extension_directory_path.get(), "log_classement_extensions.txt")
        with open(log_file_path, 'w') as log_file:
            log_file.write("\n".join(log_entries))

        self.extension_log_text.insert(tk.END, "\n".join(log_entries) + "\n")
        self.extension_log_text.see(tk.END)
        messagebox.showinfo("Information", f"Classement terminé. Log enregistré dans {log_file_path}.")

    def historique_tab(self, tab):
        ttk.Label(tab, text="Historique logiciel").grid(column=0, row=0, padx=10, pady=10)
        self.historique_text = tk.Text(tab, width=80, height=20)
        self.historique_text.grid(column=0, row=2, columnspan=3, padx=10, pady=10)

        header = f"date         action          précedent       statut"
        message = ""
        for a in self.historiques :
            message += str(a['date']) + " "
            message += a['action'] + " "
            message += a['precedent'] + " "
            message += a['statut'] + " "


        self.historique_text.insert(tk.END, message + "\n")
        self.historique_text.see(tk.END)


if __name__ == "__main__":
    app = CyberSecurityApp()
    app.mainloop()
