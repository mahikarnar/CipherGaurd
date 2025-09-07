# src/ui/components.py
"""
Reusable UI components for the Gradio interface.
"""

import gradio as gr
from typing import Tuple


def create_analysis_interface() -> Tuple[gr.Textbox, gr.Button, gr.JSON]:
    """
    Create the main password analysis interface components.
    
    Returns:
        Tuple of (input_textbox, analyze_button, results_json)
    """
    
    with gr.Row():
        with gr.Column(scale=4):
            password_input = gr.Textbox(
                label="Password to Analyze",
                type="password",
                placeholder="Enter your password here... (it will never be stored)",
                lines=1,
                max_lines=1,
                interactive=True,
                info="Your password is analyzed securely and never saved"
            )
        
        with gr.Column(scale=1):
            analyze_button = gr.Button(
                "Analyze Security",
                variant="primary",
                size="lg",
                scale=1
            )
    
    # Results display with custom styling
    with gr.Row():
        results_output = gr.HTML(
            label="Security Analysis Results",
            show_label=True
        )
    return password_input, analyze_button, results_output


def create_info_sections() -> gr.Accordion:
    """Create informational sections for the interface."""
    
    with gr.Accordion("Quick Tips", open=False) as accordion:
        gr.Markdown("""
        ### Quick Password Tips:
        
        **Strong Password Example:**
        - `MyS3cur3P@ssw0rd!` - 16 characters, mixed case, numbers, symbols
        
        **Weak Password Examples:**
        - `password123` - Common word + simple numbers
        - `qwerty12345` - Keyboard pattern
        - `John1985` - Personal info + birth year
        
        **Pro Tips:**
        - Use a passphrase: `correct horse battery staple`
        - Try a password manager for unique passwords
        - Check if your current passwords have been breached
        """)
    
    return accordion
