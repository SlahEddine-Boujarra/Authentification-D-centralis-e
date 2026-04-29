import os
import cv2
import tkinter as tk
from PIL import Image, ImageTk
import face_recognition
import numpy as np
import util


class App:
    def __init__(self):
        self.main_window = tk.Tk()
        self.main_window.geometry("1200x520+350+100")
        self.main_window.title("RCPD Biometrics System")

        # ================= DB =================
        self.db_dir = "./local_db"
        if not os.path.exists(self.db_dir):
            os.mkdir(self.db_dir)

        # ================= BUTTONS =================
        self.login_btn = util.get_button(self.main_window, "Login", "green", self.login)
        self.login_btn.place(x=750, y=150)

        self.register_btn = util.get_button(self.main_window, "Register", "gray", self.register, fg="black")
        self.register_btn.place(x=750, y=250)

        # ================= CAMERA =================
        self.webcam_label = util.get_img_label(self.main_window)
        self.webcam_label.place(x=10, y=0, width=700, height=500)

        self.cap = cv2.VideoCapture(0)
        self.update_camera()

    # ================= CAMERA LOOP =================
    def update_camera(self):
        ret, frame = self.cap.read()
        if ret:
            self.frame = frame

            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb)
            imgtk = ImageTk.PhotoImage(image=img)

            self.webcam_label.imgtk = imgtk
            self.webcam_label.configure(image=imgtk)

        self.webcam_label.after(20, self.update_camera)

    # ================= REGISTER =================
    def register(self):
        self.reg_window = tk.Toplevel(self.main_window)
        self.reg_window.geometry("400x200")

        self.entry = util.get_entry_text(self.reg_window)
        self.entry.pack()

        btn = util.get_button(self.reg_window, "Save", "green", self.save_user)
        btn.pack()

    def save_user(self):
        name = self.entry.get("1.0", "end-1c").strip()

        enc = face_recognition.face_encodings(self.frame)

        if len(enc) == 0:
            util.msg_box("Error", "No face detected")
            return

        # ================= RCPD TRANSFORMATION =================
        template = util.transform_embedding(enc[0])

        np.save(os.path.join(self.db_dir, f"{name}.npy"), template)

        util.msg_box("Success", f"{name} registered (RCPD)")
        self.reg_window.destroy()

    # ================= LOGIN =================
    def login(self):
        name = util.recognize(self.frame, self.db_dir)

        if name in ["unknown_person", "no_persons_found"]:
            util.msg_box("Access Denied", "User not recognized")
        else:
            util.msg_box("Welcome", f"Hello {name}")

    # ================= RUN =================
    def run(self):
        self.main_window.mainloop()


if __name__ == "__main__":
    app = App()
    app.run()