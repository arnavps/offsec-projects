from .crtsh import run as run_crtsh
from .hackertarget import run as run_hackertarget
from .alienvault import run as run_alienvault

MODULES = {
    'crt.sh': run_crtsh,
    'HackerTarget': run_hackertarget,
    'AlienVault': run_alienvault
}
