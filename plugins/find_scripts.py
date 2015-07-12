from CTPlugin import ConsolePlugin
from CTCore import srcHTMLParser

class find_scripts(ConsolePlugin):

    description = "Finds external scripts included in the object body"
    author = "omriher"

    def run(self, args):
        if len(args) > 0:
            # Get the conversation ID
            id = int(args[0])
            if self.is_valid_id(id):
                name = self.get_name_by_id(id)
                print "[.] Searching for external scripts in object {} ({})...".format(str(id),name)

                # Get response body as text even in case it was Gzipped
                response_body = self.get_plaintext_body_by_id(id)

                # Create Parser instance and search for <script src="...
                parser = srcHTMLParser("script")
                parser.feed(response_body)
                parser.print_objects()
            else:
                print "Invalid conversation ID {}".format(str(id))
        else:
            return "No arguments given"