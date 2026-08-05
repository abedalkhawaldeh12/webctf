import random
from typing import Optional
from core.ui import console

class NarratorEngine:
    """
    Narrator Engine - The Interactive UX Layer (Human-like Pentester)
    
    Acts as a conversational partner explaining what it is doing, why it's doing it,
    and making decisions. It alerts the user of critical actions without pausing.
    """

    def __init__(self):
        self.recon_phrases = [
            "Just having a quick look around...",
            "Poking at the server to see what falls out...",
            "Mapping the territory...",
            "Digging through the trash (comments & hidden files)..."
        ]
        self.action_phrases = [
            "Alright, let's try this...",
            "Sending the payload now...",
            "Time to break things...",
            "Let's see if they patched this..."
        ]

    def speak_phase_intro(self, phase_name: str, description: str):
        """Introduces a new phase in a conversational tone."""
        console.print(f"\n[bold magenta]=== {phase_name} ===[/bold magenta]")
        console.print(f"[bold italic white]Me:[/bold italic white] [italic]{description}[/italic]\n")

    def speak_thinking(self, message: str):
        """Simulates 'thinking out loud' before taking action."""
        console.print(f"[dim italic yellow]Hmm... {message}[/dim italic yellow]")

    def speak_recon(self, message: str):
        """Prints reconnaissance tasks in a faint/dim style."""
        console.print(f"[dim italic]   * {message}[/dim italic]")

    def speak_action(self, message: str):
        """Prints active exploitation attempts clearly."""
        prefix = random.choice(self.action_phrases)
        console.print(f"[bold cyan]>> {prefix} {message}[/bold cyan]")

    def speak_critical_action(self, message: str):
        """Informs the user of a dangerous action (e.g., dropping DB) but does NOT pause."""
        console.print(f"[bold red blink]![/bold red blink] [bold red]CRITICAL ACTION:[/bold red] [white]{message}[/white]")
        console.print(f"[dim red]Proceeding automatically...[/dim red]")

    def speak_success(self, message: str):
        """Prints successful discoveries with high impact."""
        console.print(f"[bold green]>> [BINGO!] {message}[/bold green]")

    def speak_warning(self, message: str):
        """Prints warnings or failed attempts."""
        console.print(f"[bold yellow]>> [Oops] {message}[/bold yellow]")

    def interactive_flag_check(self, flag: str) -> bool:
        """
        Interactive prompt when a flag is found.
        First confirms if the text is the actual flag, then asks for escalation.
        Returns True if more flags exist (needs escalation).
        """
        console.print(f"\n[bold magenta]==================================================[/bold magenta]")
        console.print(f"[bold magenta]🎉 I THINK I FOUND SOMETHING: [white]{flag}[/white][/bold magenta]")
        console.print(f"[bold magenta]==================================================[/bold magenta]\n")
        
        while True:
            is_flag = input(f"Is '{flag}' the flag you are looking for? (y/n): ").strip().lower()
            if is_flag in ['y', 'yes']:
                console.print("[bold green]Awesome! One down.[/bold green]\n")
                break
            elif is_flag in ['n', 'no']:
                console.print("[dim]Ah, my bad. False alarm. I'll keep looking.[/dim]")
                return False
            else:
                console.print("[dim]Please answer 'y' or 'n'[/dim]")

        while True:
            response = input("Are there MORE flags in this challenge? (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                console.print("\n[bold red]>> Roger that. I'm taking the gloves off. Initiating Vulnerability Chaining for deeper escalation...[/bold red]")
                return True
            elif response in ['n', 'no']:
                console.print("\n[bold green]>> Excellent! We owned this one. Challenge completed.[/bold green]")
                return False
            else:
                console.print("[dim]Please answer 'y' or 'n'[/dim]")

