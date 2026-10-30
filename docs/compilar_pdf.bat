@echo off
echo ==============================================================================
echo    COMPILANDO INFORME FINAL (HACKATHON: OPERACION HUELLA DIGITAL)
echo    Autores: Christian Salinas y Alddrin Venegas
echo ==============================================================================

where xelatex >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [*] Detectado motor XeLaTeX. Compilando con tipografia Arial...
    xelatex -interaction=nonstopmode INFORME_FINAL_HACKATHON.tex
    xelatex -interaction=nonstopmode INFORME_FINAL_HACKATHON.tex
    goto check_result
)

where pdflatex >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [*] Detectado motor pdfLaTeX. Compilando con tipografia Arial/Helvetica...
    pdflatex -interaction=nonstopmode INFORME_FINAL_HACKATHON.tex
    pdflatex -interaction=nonstopmode INFORME_FINAL_HACKATHON.tex
    goto check_result
)

echo [AVISO] No se encontro xelatex ni pdflatex en el PATH local de Windows.
echo.
echo Puedes compilar el informe directamente en Overleaf.com:
echo 1. Crea un nuevo proyecto en Overleaf.
echo 2. Sube el archivo INFORME_FINAL_HACKATHON.tex.
echo 3. Presiona 'Recompile' (compatible con XeLaTeX y pdfLaTeX).
echo.
pause
exit /b 1

:check_result
if exist INFORME_FINAL_HACKATHON.pdf (
    echo.
    echo ==============================================================================
    echo [EXITO] PDF generado exitosamente: INFORME_FINAL_HACKATHON.pdf
    echo ==============================================================================
    start INFORME_FINAL_HACKATHON.pdf
) else (
    echo.
    echo [ERROR] La compilacion genero errores. Revisa el archivo INFORME_FINAL_HACKATHON.log.
)

pause
