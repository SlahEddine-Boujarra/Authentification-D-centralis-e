@echo off
echo ========================================================
echo  SERVEUR SSI + ZKP (HTTPS + JWT)
echo  Aucune donnee biometrique n'est stockee sur ce serveur
echo ========================================================
cd serveur
del serveur_db.sqlite 2>nul
python api.py
pause
