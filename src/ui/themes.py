# src/ui/themes.py
"""
Custom themes and styling for the Gradio interface.
"""

import gradio as gr


def get_custom_theme() -> gr.Theme:
    """
    Create a custom Gradio theme with modern dark styling.
    
    Returns:
        gr.Theme: Custom theme configuration
    """
    
    return gr.themes.Soft(
        primary_hue="blue",
        secondary_hue="cyan",
        neutral_hue="slate",
        spacing_size="lg",
        radius_size="md"
    ).set(
        # Dark theme colors
        body_background_fill="*neutral_950",
        body_text_color="*neutral_200",
        
        # Block styling
        block_background_fill="*neutral_900",
        block_border_color="*neutral_800",
        block_title_text_color="*neutral_100",
        block_label_text_color="*neutral_300",
        
        # Input styling
        input_background_fill="*neutral_800",
        input_background_fill_focus="*neutral_750",
        input_border_color="*neutral_700",
        input_border_color_focus="*primary_500",
        input_placeholder_color="*neutral_400",
        
        # Button styling
        button_primary_background_fill="*primary_600",
        button_primary_background_fill_hover="*primary_500",
        button_primary_background_fill_dark="*primary_700",
        button_primary_text_color="white",
        button_primary_border_color="*primary_600",
        
        # Panel styling
        panel_background_fill="*neutral_850",
        panel_border_color="*neutral_700",
        
        # Accordion styling
        accordion_text_color="*neutral_200",
        
        # JSON output styling
        color_accent="*primary_500",
        color_accent_soft="*primary_100"
    )


def get_custom_css() -> str:
    """
    Get custom CSS for additional styling and animations.
    
    Returns:
        str: CSS styling rules
    """
    
    return """
    /* Main container styling */
    .gradio-container {
        max-width: 1200px !important;
        margin: 0 auto !important;
        padding: 20px !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }
    
    /* Header styling */
    .gradio-container h1 {
        background: linear-gradient(135deg, #3b82f6, #06b6d4) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        text-align: center !important;
        margin-bottom: 10px !important;
    }
    
    /* Password input special styling */
    input[type="password"] {
        font-family: 'Monaco', 'Consolas', 'Courier New', monospace !important;
        font-size: 16px !important;
        letter-spacing: 1px !important;
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(6, 182, 212, 0.1)) !important;
        border: 2px solid transparent !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
    }
    
    input[type="password"]:focus {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
        background: rgba(59, 130, 246, 0.05) !important;
    }
    
    /* Button animations */
    button {
        transition: all 0.3s ease !important;
        font-weight: 600 !important;
    }
    
    .btn-primary {
        background: linear-gradient(135deg, #3b82f6, #1d4ed8) !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 12px 24px !important;
        font-size: 16px !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3) !important;
    }
    
    .btn-primary:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 20px rgba(59, 130, 246, 0.4) !important;
        background: linear-gradient(135deg, #1d4ed8, #1e40af) !important;
    }
    
    .btn-primary:active {
        transform: translateY(0) !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3) !important;
    }
    
    /* JSON results styling */
    .json-holder {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8), rgba(30, 41, 59, 0.8)) !important;
        border: 1px solid rgba(59, 130, 246, 0.2) !important;
        border-radius: 12px !important;
        padding: 20px !important;
        backdrop-filter: blur(10px) !important;
    }
    
    .json-tree {
        font-family: 'Monaco', 'Consolas', 'Courier New', monospace !important;
        font-size: 14px !important;
        line-height: 1.6 !important;
    }
    
    /* Results with emoji styling */
    .json-tree .json-key {
        color: #06b6d4 !important;
        font-weight: 600 !important;
    }
    
    .json-tree .json-string {
        color: #10b981 !important;
    }
    
    .json-tree .json-number {
        color: #f59e0b !important;
    }
    
    /* Strength meter visualization */
    .strength-meter {
        font-family: 'Courier New', monospace !important;
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)) !important;
        padding: 15px !important;
        border-radius: 8px !important;
        border: 1px solid rgba(59, 130, 246, 0.3) !important;
        margin: 10px 0 !important;
    }
    
    /* Examples styling */
    .examples {
        margin-top: 30px !important;
        padding: 20px !important;
        background: rgba(15, 23, 42, 0.5) !important;
        border-radius: 12px !important;
        border: 1px solid rgba(59, 130, 246, 0.2) !important;
    }
    
    .examples .example-btn {
        background: rgba(59, 130, 246, 0.1) !important;
        border: 1px solid rgba(59, 130, 246, 0.3) !important;
        color: #e2e8f0 !important;
        border-radius: 6px !important;
        padding: 8px 16px !important;
        margin: 4px !important;
        transition: all 0.2s ease !important;
    }
    
    .examples .example-btn:hover {
        background: rgba(59, 130, 246, 0.2) !important;
        border-color: rgba(59, 130, 246, 0.5) !important;
        transform: scale(1.02) !important;
    }
    
    /* Accordion styling */
    .accordion {
        margin-top: 30px !important;
        border-radius: 12px !important;
        border: 1px solid rgba(59, 130, 246, 0.2) !important;
        background: rgba(15, 23, 42, 0.3) !important;
    }
    
    .accordion summary {
        padding: 16px 20px !important;
        font-weight: 600 !important;
        color: #06b6d4 !important;
        cursor: pointer !important;
        border-radius: 12px !important;
        transition: background 0.2s ease !important;
    }
    
    .accordion summary:hover {
        background: rgba(59, 130, 246, 0.1) !important;
    }
    
    .accordion-content {
        padding: 0 20px 20px 20px !important;
    }
    
    /* Security indicators */
    .security-excellent { color: #10b981 !important; }
    .security-good { color: #06b6d4 !important; }
    .security-fair { color: #f59e0b !important; }
    .security-weak { color: #f97316 !important; }
    .security-poor { color: #ef4444 !important; }
    
    /* Loading animations */
    .loading {
        opacity: 0.6 !important;
        pointer-events: none !important;
        position: relative !important;
    }
    
    .loading::after {
        content: '' !important;
        position: absolute !important;
        top: 50% !important;
        left: 50% !important;
        width: 20px !important;
        height: 20px !important;
        margin: -10px 0 0 -10px !important;
        border: 2px solid transparent !important;
        border-top: 2px solid #3b82f6 !important;
        border-radius: 50% !important;
        animation: spin 1s linear infinite !important;
    }
    
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
        .gradio-container {
            padding: 10px !important;
        }
        
        input[type="password"] {
            font-size: 14px !important;
        }
        
        .btn-primary {
            padding: 10px 20px !important;
            font-size: 14px !important;
        }
        
        .json-holder {
            padding: 15px !important;
        }
    }
    
    /* Smooth scrolling */
    html {
        scroll-behavior: smooth !important;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px !important;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(30, 41, 59, 0.3) !important;
        border-radius: 4px !important;
    }
    
    ::-webkit-scrollbar-thumb {
        background: rgba(59, 130, 246, 0.6) !important;
        border-radius: 4px !important;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(59, 130, 246, 0.8) !important;
    }
    """


# Example usage for testing components
if __name__ == "__main__":
    # Test the theme and components
    theme = get_custom_theme()
    css = get_custom_css()
    
    print("Theme created successfully")
    print(f"CSS length: {len(css)} characters")
    
    # Create a simple test interface
    with gr.Blocks(theme=theme, css=css) as demo:
        gr.Markdown("# Test Interface")
        
        password_input, analyze_button, results_output = create_analysis_interface()
        info_sections = create_info_sections()
        
        def dummy_analysis(password):
            return {"Test": "This is a test result", "Password Length": len(password)}
        
        analyze_button.click(dummy_analysis, inputs=password_input, outputs=results_output)