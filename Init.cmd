@echo off
@rem Run after Setup.cmd, or as needed, to set useful aliases and environment variables.

@rem Get the Git username for use in macros below.
set __GitUserName=%USERNAME%
for /f %%n in ('git config user.name') do set __GitUserName=%%n
@rem Remove spaces in case the user has used a full name instead of GitHub username.
set __GitUserName=%__GitUserName: =%

echo.
echo ==========================================================================
echo Ensuring a good editor in place for Git commits on the command line.
echo ==========================================================================
echo.
git config --global core.editor
if ERRORLEVEL 1 git config --global core.editor "notepad"

echo.
echo ==========================================================================
echo Setting aliases for easier command line experience
echo ==========================================================================
echo.
doskey /macrofile=%~dp0aliases.txt
doskey /macros


exit /b 0
