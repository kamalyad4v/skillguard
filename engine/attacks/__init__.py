from engine.attacks.sqli import SQLiAttack
from engine.attacks.xss import XSSAttack
from engine.attacks.dirbuster import DirBusterAttack
from engine.attacks.csrf import CSRFAttack
from engine.attacks.auth_brute import AuthBruteAttack

ATTACK_REGISTRY = {
    "sqli": SQLiAttack,
    "xss": XSSAttack,
    "dirbuster": DirBusterAttack,
    "csrf": CSRFAttack,
    "auth_brute": AuthBruteAttack,
}

ALL_ATTACKS = list(ATTACK_REGISTRY.keys())
