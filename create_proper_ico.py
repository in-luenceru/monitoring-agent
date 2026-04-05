#!/usr/bin/env python3
"""
Create proper Windows ICO files for the monitoring agent
"""
from PIL import Image, ImageDraw
import io

def create_monitoring_agent_logo():
    """Create a monitoring agent logo with green and blue colors"""
    # Create a 48x48 image with transparent background
    size = 48
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Colors from the user's logo: green #94D63D and blue #2E7DFF
    green = (148, 214, 61, 255)
    blue = (46, 125, 255, 255)
    
    # Create a shield-like logo for monitoring/security
    # Draw outer border in blue
    draw.ellipse([2, 2, size-2, size-2], outline=blue, width=3)
    
    # Draw inner circle in green
    draw.ellipse([8, 8, size-8, size-8], fill=green)
    
    # Draw "M" for Monitoring in blue
    center_x, center_y = size // 2, size // 2
    font_size = 20
    
    # Simple "M" shape using lines
    # Left vertical line
    draw.line([center_x-8, center_y-8, center_x-8, center_y+8], fill=blue, width=3)
    # Right vertical line
    draw.line([center_x+8, center_y-8, center_x+8, center_y+8], fill=blue, width=3)
    # Left diagonal
    draw.line([center_x-8, center_y-8, center_x, center_y], fill=blue, width=3)
    # Right diagonal
    draw.line([center_x+8, center_y-8, center_x, center_y], fill=blue, width=3)
    
    return img

def create_ico_file(image, filepath):
    """Create a proper Windows ICO file with multiple sizes"""
    # Create different sizes for the ICO file
    sizes = [16, 32, 48]
    images = []
    
    for size in sizes:
        # Resize the image
        resized = image.resize((size, size), Image.Resampling.LANCZOS)
        images.append(resized)
    
    # Save as ICO file
    images[0].save(filepath, format='ICO', sizes=[(img.width, img.height) for img in images])

def main():
    # Create the logo
    logo = create_monitoring_agent_logo()
    
    # Create ICO files
    create_ico_file(logo, '/home/anandhu/Desktop/monitoring_agent/src/win32/favicon.ico')
    create_ico_file(logo, '/home/anandhu/Desktop/monitoring_agent/src/win32/install.ico')
    create_ico_file(logo, '/home/anandhu/Desktop/monitoring_agent/src/win32/uninstall.ico')
    
    print("Created proper ICO files:")
    print("- favicon.ico")
    print("- install.ico") 
    print("- uninstall.ico")

if __name__ == "__main__":
    main()