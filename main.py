import os.path
import datetime
import tkinter as tk
import cv2
from PIL import Image, ImageTk
import face_recognition
import util

MOCK_SERVER_DB = {}

class App:
    def __init__(self):
        self.main_window = tk.Tk()
        self.main_window.geometry("1200x520+350+100")
        self.main_window.title("Prototype Biométrique Zero-Knowledge")

        self.login_button_main_window = util.get_button(self.main_window, 'login', 'green', self.login)
        self.login_button_main_window.place(x=750, y=150)

        self.register_new_user_button_main_window = util.get_button(self.main_window, 'register', 'gray', self.register_new_user, fg='black')
        self.register_new_user_button_main_window.place(x=750, y=250)

        self.webcam_label = util.get_img_label(self.main_window)
        self.webcam_label.place(x=10, y=0, width=700, height=500)

        self.add_webcam(self.webcam_label)

        self.db_dir = './local_db' # Stocke uniquement Fragment A
        if not os.path.exists(self.db_dir): os.mkdir(self.db_dir)

    def add_webcam(self, label):
        self.cap = cv2.VideoCapture(0)
        self._label = label
        self.process_webcam()

    def process_webcam(self):
        ret, frame = self.cap.read()
        if ret:
            self.most_recent_capture_arr = frame
            img_ = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            self.most_recent_capture_pil = Image.fromarray(img_)
            imgtk = ImageTk.PhotoImage(image=self.most_recent_capture_pil)
            self._label.imgtk = imgtk
            self._label.configure(image=imgtk)
        self._label.after(20, self.process_webcam)

    def login(self):
        # Utilise la nouvelle fonction recognize avec fragmentation
        name = util.recognize(self.most_recent_capture_arr, self.db_dir, MOCK_SERVER_DB)

        if name in ['unknown_person', 'no_persons_found']:
            util.msg_box('Erreur', 'Utilisateur inconnu ou visage non détecté.')
        else:
            util.msg_box('Succès', f'Bienvenue, {name}. Authentification Zero-Knowledge réussie !')

    def register_new_user(self):
        self.register_window = tk.Toplevel(self.main_window)
        self.register_window.geometry("1200x520+370+120")
        
        self.capture_label = util.get_img_label(self.register_window)
        self.capture_label.place(x=10, y=0, width=700, height=500)
        
        # Capture de l'image actuelle
        imgtk = ImageTk.PhotoImage(image=self.most_recent_capture_pil)
        self.capture_label.imgtk = imgtk
        self.capture_label.configure(image=imgtk)
        self.register_capture = self.most_recent_capture_arr.copy()

        self.entry_name = util.get_entry_text(self.register_window)
        self.entry_name.place(x=750, y=150)
        
        util.get_button(self.register_window, 'Accept', 'green', self.accept_register).place(x=750, y=300)

    def accept_register(self):
        name = self.entry_name.get(1.0, "end-1c").strip()
        embeddings = face_recognition.face_encodings(self.register_capture)
        
        if len(embeddings) > 0:
           
            enc_a, enc_b = util.fragment_and_encrypt(embeddings[0])
            
            
            with open(os.path.join(self.db_dir, f'{name}_fragA.bin'), 'wb') as f:
                f.write(enc_a)
            
            
            MOCK_SERVER_DB[name] = enc_b
            
            util.msg_box('Succès', f'Utilisateur {name} enregistré. Fragments dispersés !')
            self.register_window.destroy()
        else:
            util.msg_box('Erreur', 'Aucun visage détecté.')

    def start(self):
        self.main_window.mainloop()

if __name__ == "__main__":
    app = App()
    app.start()