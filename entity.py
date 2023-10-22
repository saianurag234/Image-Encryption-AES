from dataclasses import dataclass

@dataclass
class image_metadata:
    image_height:int
    image_width:int
    is_colour:bool
    colour_channels:int