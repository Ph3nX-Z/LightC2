import random



def set_random_color(char):
    CEND      = '\33[0m'
    CBOLD     = '\33[1m'
    CITALIC   = '\33[3m'
    CURL      = '\33[4m'
    CBLINK    = '\33[5m'
    CBLINK2   = '\33[6m'
    CSELECTED = '\33[7m'

    colors1 = "\33["+str(random.randint(91,94))+"m"
    colors2 = "\33["+str(random.randint(31,34))+"m"
    color = random.choice((colors1,colors2))
    char = color+char+CEND
    return char

def gen_header():

    header1 = """
██      ██  ██████  ██   ██ ████████  ██████ ██████  
██      ██ ██       ██   ██    ██    ██           ██ 
██      ██ ██   ███ ███████    ██    ██       █████  
██      ██ ██    ██ ██   ██    ██    ██      ██      
███████ ██  ██████  ██   ██    ██     ██████ ███████ 
"""

    header2 = '''

 ██▓     ██▓  ▄████  ██░ ██ ▄▄▄█████▓ ▄████▄   ▄████▄  
▓██▒    ▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▀ ▀█  
▒██░    ▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░▒▓█    ▄ ▒▓█    ▄ 
▒██░    ░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒▓▓▄ ▄██▒
░██████▒░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ ▒ ▓███▀ ░▒ ▓███▀ ░
░ ▒░▓  ░░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   ░ ░▒ ▒  ░░ ░▒ ▒  ░
░ ░ ▒  ░ ▒ ░  ░   ░  ▒ ░▒░ ░    ░      ░  ▒     ░  ▒   
  ░ ░    ▒ ░░ ░   ░  ░  ░░ ░  ░      ░        ░        
    ░  ░ ░        ░  ░  ░  ░         ░ ░      ░ ░      
                                     ░        ░        '''

    header3="""


██╗     ██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗ 
██║     ██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝╚════██╗
██║     ██║██║  ███╗███████║   ██║   ██║      █████╔╝
██║     ██║██║   ██║██╔══██║   ██║   ██║     ██╔═══╝ 
███████╗██║╚██████╔╝██║  ██║   ██║   ╚██████╗███████╗
╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚══════╝
"""

    return set_random_color(random.choice((header1,header2,header3)))


def gen_wizard():
    wizard = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡰⠉⠀⠀⠉⠻⢦⡀⠀⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⠁⠀⠀⠀⠀⠈⣶⣝⣺⢷⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡗⠂⠀⠀⠀⠁⠐⠺⡌⠁⠈⠛⠂⠀⠀
⠀⠀⠀⢀⣠⠴⠚⠊⠉⠉⠁⠈⠉⠉⠑⠓⠦⣄⡀⠀⠀⠀
⢀⣴⣾⣭⡤⢤⣤⣄⣀⣀⣀⣀⣀⣀⣠⣤⡤⢤⣭⣷⣦⡀
⠈⢯⣿⡿⣁⡜⣨⠀⠷⣲⡞⢻⣖⠾⠀⡅⢳⣈⢿⣟⡽⠁     \33[35m[LightC2 Wizard]\33[0m
⠀⠀⠈⠙⡟⡜⣸⡀⠀⡅⠇⠘⠢⠀⢀⣇⢣⢻⠋⠁⠀⠀
⠀⠀⠀⠰⡾⡰⡏⠛⠚⠋⣉⣍⠙⠓⠛⢹⢆⢷⠆⠀⠀⠀
⠀⠀⠀⠀⢷⠡⢹⠒⢖⡬⠄⠀⢭⡲⠒⡏⠈⡾⠀⠀⠀⠀
⠀⠀⠀⠀⠸⢇⣏⣦⠀⠀⠀⠀⠀⠀⣴⣽⡼⠇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠈⠉⠻⣴⠀⠀⣤⠟⠁⠁⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀

"""
    return wizard

if __name__=='__main__':
    print(set_random_color(gen_header()))