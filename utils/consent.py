def ask_authorization(target: str) -> bool:
    print(f"\n[!] Stai per avviare un pentest su: {target}")
    print("[!] Questa operazione è LEGALE solo se hai esplicita autorizzazione scritta.")
    ans = input("\nConfermi di possedere autorizzazione scritta per testare questo target? [si/no]: ")
    return ans.strip().lower() in ("si", "yes", "s", "y")