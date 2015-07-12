from CTPlugin import ConsolePlugin
from CTCore import ungzip

class print_body(ConsolePlugin):

    description = "Prints the body of a conversation and ungzip if needed"
    author = "omriher"

    def run(self, args):
        id = int(args[0])
        if self.is_valid_id(id):
            if id < len(self.conversations) and self.conversations[id].magic_ext == "GZ":
                data, name = ungzip(id) # Ungzip imported from CTCore
            else:
                data = self.get_body_by_id(id)
        else:
            print "invalid id"