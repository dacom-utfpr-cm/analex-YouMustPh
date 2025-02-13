from automata.fa.Moore import Moore
import sys, os

from myerror import MyError

error_handler = MyError('LexerErrors')

# Constants
global check_cm
global check_key


# Reserved words
reservedWords = ['if', 'else', 'int', 'float', 'return', 'void', 'while']

# Valid letters for reserved words
validLetters = ['i', 'e', 'r', 'v', 'w', 'f', 'n', 'l', 't', 's', 'o', 'a', 'u', 'd', 'h']

# Start reserved letters
startReservedLetters = ['i', 'e', 'f', 'v', 'w', 'r']

# Characters that can be right after an identifier
validPosIdCharacters = ['(', ')', '[', ']', '{', '}', ' ', '\n', ';', ',', '+', '-', '*', '/', '<', '=', '>', '!']

# Digits
digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# Invalid characters
invalidCharacters = ['@', '#', '$', '%', '&', '?', '´', '`', '¨', '^', '~',
                     'º', 'ª', '§', '¬', '¢', '£', '³', '²', '¹', 'µ', '§',
                     'ª', 'º', '°', 'ç', 'Ç', 'ã', 'Ã', 'õ', 'Õ', 'á', 'Á',
                     'é', 'É', 'í', 'Í', 'ó', 'Ó', 'ú', 'Ú', 'à', 'À', 'è',
                     'È', 'ì', 'Ì', 'ò', 'Ò', 'ù', 'Ù', 'â', 'Â', 'ê', 'Ê',
                     'î', 'Î', 'ô', 'Ô', 'û', 'Û', 'ä', 'Ä', 'ë', 'Ë', 'ï', 
                     'Ï', 'ö', 'Ö', 'ü', 'Ü', 'ÿ', 'Ÿ', 'ç', 'Ç', 'ñ', 'Ñ', 
                     'ß', 'œ', 'Œ', 'æ', 'Æ', 'å', 'Å', 'ø', 'Ø', 'þ', 'Þ', 
                     'ð', 'Ð', 'µ', 'µ', '€', '£', '¥', '¢', '§', '©', '®', 
                     '™', '•', '¶', '÷', '×', '±', '∞', '∑', '∏', 'π', '√', 
                     '∫', '≠', '≈', '≤', '≥', '∂', '∆', '∑', '∏', '∫', '∂', 
                     '∆', '√', '∞', '∈', '∉', '∩', '∪', '∅', '∧', '∨', '¬', 
                     '∀', '∃', '∄', '∑', '∏', '∫', '∂', '∆', '√', '∞', '∈', 
                     '∉', '∩', '∪', '∅', '∧', '∨', '¬', '∀', '∃', '∄', '∑', 
                     '∏', '∫', '∂', '∆', '√', '∞', '∈', '∉', '∩', '∪', '∅', 
                     '∧', '∨', '¬', '∀', '∃', '∄', '∑', '∏', '∫', '∂', '∆', 
                     '√', '∞', '∈', '∉', '∩', '∪', '∅', '∧', '∨', '¬', '∀', 
                     '∃', '∄', '∑', '∏', '∫', '∂', '∆', '√', '∞', '∈', '∉', 
                     '∩', '∪', '∅', '∧', '∨', '¬', '∀', '∃', '∄', '∑', '∏', 
                     '∫', '∂', '∆', '√', '∞', '∈', '∉', '∩', '∪', '∅', '∧', 
                     '∨', '¬', '∀', '∃', '∄', '∑', '∏', '∫', '∂', '∆', '√', 
                     '∞', '∈', '∉', '∩', '∪', '∅', '∧', '∨', '¬', '∀', '∃', 
                     '∄', '∑', '∏', '∫', '∂', '∆', '√', '∞', '∈', '∉', '∩', 
                     '∪', '∅', '∧', '∨', '¬', '∀', '∃', '∄', '∑', '∏', '∫', 
                     '∂', '∆', '√', '∞', '∈', '∉', '∩', '∪', '∅', '∧', '∨', 
                     '¬']

moore = Moore(
  # Moore States
  ['q0', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9', 'q10', 
   'q11', 'q12', 'q13', 'q14', 'q15', 'q16', 'q18', 'q19', 'q20', 'q21',
   'q22', 'q23', 'q24', 'q25', 'q26', 'q27', 'q28', 'q29', 'q30', 'q31',
   'q32', 'q33', 'q34', 'q35', 'q36', 'q37', 'q38', 'q39', 'q40', 'q41', 
   'q42', 'q43', 'q44', 'q45', 'q46', 'q47', 'q48', 'q49', 'q50', 'q51', 
   'q52', 'q53', 'q54', 'q55', 'q56'],
  # Moore Input Alphabet
  ['i', 'e', 'r', 'v', 'w', 'f', 'n', 'l', 't', 's', 'o', 'a', 'u', 'd', 'h',
      '+', '-', '*', '/', '<', '=', '>', '!', ';', ',', '(', ')', '[',
   ']', '{', '}', ' ', '\n', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'],
  # Moore output alphabet
  ['IF', 'ELSE', 'INT', 'RETURN', 'VOID', 'WHILE', 'PLUS', 'MINUS', 'TIMES',
   'DIVIDE', 'LESS', 'LESS_EQUAL', 'GREATER', 'GREATER_EQUAL', 'DIFFERENT',
   'SEMICOLON', 'COMMA', 'LPAREN', 'RPAREN', 'LBRACKETS', 'RBRACKETS', 'LBRACES',
   'RBRACES', 'ATTRIBUTION', 'EQUALS', 'NUMBER'],
  # Moore transitions
  {
    'q0': { 'i': 'q1', 'e': 'q3', 'r': 'q10', 'v': 'q15', 'w': 'q19', '+': 'q23',
           'a': 'q50', 'u': 'q50', 'd': 'q50', 'h': 'q50', 's': 'q50', 'o': 'q50',
            't': 'q50', 'l': 'q50', 'n': 'q50', 'f': 'q51', '-': 'q24', '*': 'q25',
            '/': 'q26', '<': 'q27', '>': 'q30', '=': 'q33', '!': 'q34', ';': 'q44',
            ',': 'q45', '(': 'q37', ')': 'q38', '[': 'q39', ']': 'q40', '{': 'q41',
            '}': 'q42', '0': 'q48', '1': 'q48', '2': 'q48', '3': 'q48', '4': 'q48',
            '5': 'q48', '6': 'q48', '7': 'q48', '8': 'q48', '9': 'q48', ' ': 'q0',
            '\n': 'q0' },
    'q1': { 'f': 'q2', 'n': 'q7' },
    'q2': { '' : 'q0' },
    'q3': { 'l': 'q4', 't': 'q11' },
    'q4': { 's': 'q5' },
    'q5': { 'e': 'q6' },
    'q6': { '' : 'q0' },
    'q7': { 't': 'q8' },
    'q8': { '\n': 'q9', ' ': 'q9' },
    'q9': { '' : 'q0' },
    'q10': { 'e': 'q46' },
    'q11': { 'u': 'q12' },
    'q12': { 'r': 'q13' },
    'q13': { 'n': 'q14' },
    'q14': { '' : 'q0' },
    'q15': { 'o': 'q16', '' : 'q50' },
    'q16': { 'i': 'q17' },
    'q17': { 'd': 'q18' },
    'q18': { '' : 'q0' },
    'q19': { 'h': 'q20' },
    'q20': { 'i': 'q47' },
    'q21': { 'e': 'q22' },
    'q22': { '' : 'q0' },
    'q23': { '' : 'q0' },
    'q24': { '' : 'q56', '1': 'q48', '2': 'q48', '3': 'q48', '4': 'q48', '5': 'q48',
             '6': 'q48', '7': 'q48', '8': 'q48', '9': 'q48' },
    'q25': { '' : 'q0' },
    'q26': { '' : 'q0' },
    'q27': { '': 'q28', '=': 'q29' },
    'q28': { '' : 'q0' },
    'q29': { '' : 'q0' },
    'q30': { '': 'q31', '=': 'q32' },
    'q31': { '' : 'q0' },
    'q32': { '' : 'q0' },
    'q33': { '': 'q43', '=': 'q35' },
    'q34': { '=': 'q36' },
    'q35': { '' : 'q0' },
    'q36': { '' : 'q0' },
    'q37': { '' : 'q0' },
    'q38': { '' : 'q0' },
    'q39': { '' : 'q0' },
    'q40': { '' : 'q0' },
    'q41': { '' : 'q0' },
    'q42': { '' : 'q0' },
    'q43': { '' : 'q0' },
    'q44': { '' : 'q0' },
    'q45': { '' : 'q0' },
    'q46': { 't': 'q11' },
    'q47': { 'l': 'q21' },
    'q48': { '0': 'q48', '1': 'q48', '2': 'q48', '3': 'q48', '4': 'q48', '5': 'q48',
             '6': 'q48', '7': 'q48', '8': 'q48', '9': 'q48', '': 'q49'},
    'q49': { '' : 'q0' },
    'q50': { '' : 'q0' },
    'q51': { 'l': 'q52' },
    'q52': { 'o': 'q53' },
    'q53': { 'a': 'q54' },
    'q54': { 't': 'q55' },
    'q55': { '' : 'q0' },
    'q56': { '' : 'q0' },
  },
  # Initial state
  'q0',
  # Output state
  {
    'q0': '',
    'q1': '',
    'q2': 'IF',
    'q3': '',
    'q4': '',
    'q5': '',
    'q6': 'ELSE',
    'q7': '',
    'q8': '',
    'q9': 'INT',
    'q10': '',
    'q11': '',
    'q12': '',
    'q13': '',
    'q14': 'RETURN',
    'q15': '',
    'q16': '',
    'q17': '',
    'q18': 'VOID',
    'q19': '',
    'q20': '',
    'q21': '',
    'q22': 'WHILE',
    'q23': 'PLUS',
    'q24': '',
    'q25': 'TIMES',
    'q26': 'DIVIDE',
    'q27': '',
    'q28': 'LESS',
    'q29': 'LESS_EQUAL',
    'q30': '',
    'q31': 'GREATER',
    'q32': 'GREATER_EQUAL',
    'q33': '',
    'q34': '',
    'q35': 'EQUALS',
    'q36': 'DIFFERENT',
    'q37': 'LPAREN',
    'q38': 'RPAREN',
    'q39': 'LBRACKETS',
    'q40': 'RBRACKETS',
    'q41': 'LBRACES',
    'q42': 'RBRACES',
    'q43': 'ATTRIBUTION',
    'q44': 'SEMICOLON',
    'q45': 'COMMA',
    'q46': '',
    'q47': '',
    'q48': '',
    'q49': 'NUMBER',
    'q50': '',
    'q51': '',
    'q52': '',
    'q53': '',
    'q54': '',
    'q55': 'FLOAT',
    'q56': 'MINUS',
  },
)

# Function to analyze the source code
def analysis(sourceFileString):
  # Variables
  state = moore.initial_state
  outputTable = moore.output_table
  inputAlphabet = moore.input_alphabet
  tokens = []
  var = ''
  output = 'q0'
  startReserved = False
  startOfComment = False
  isComment = False
  endOfComment = False
  startNumber = False
  endNumber = False
  previousSymbol = ''
  check_key = False

  # loop through the source code
  for symbol in sourceFileString:    
    
    # Number lenght handling
    if symbol in digits and not startNumber:
      startNumber = True    
    if startNumber and symbol not in digits:
      startNumber = False
      endNumber = True
    
    # Comment handling
    if startOfComment and symbol != '*':
      startOfComment = False    
    if isComment and symbol == '*' and not endOfComment:
      endOfComment = True      
    if isComment and symbol == '/' and endOfComment:
      isComment = False
      endOfComment = False
      continue    
    if symbol == '*' and startOfComment:
      tokens.pop()
      startOfComment = False
      isComment = True    
    if symbol == '/' and not startOfComment:
      startOfComment = True    
    if isComment:
      continue
    
    # Invalid character handling
    if symbol in invalidCharacters:
      # raise IOError(error_handler.newError(check_key, 'ERR-LEX-INV-CHAR'))
      tokens.append(('ERROR', 'ERR-LEX-INV-CHAR'))    
      
    # Valid character handling
    if (((symbol in inputAlphabet) and var == '' )):   
        
        # Minus handling when it is not a number
        if (previousSymbol == '-' and symbol != ' ' and symbol != '\n' and symbol not in digits):
            tokens.append(('MINUS', symbol))
            startReserved = False
        
        # Transition to the next state when the state has a empty transition
        if ('' in moore.transitions[state] and (symbol == ' ' or (previousSymbol == '-' and symbol not in digits))) or endNumber:
            output = moore.transitions[state]['']
            state = output
            endNumber = False
            if outputTable[output] != '':
                tokens.append((outputTable[output], symbol))
  
        # ID handling when symbols in the reserved words are found   
        if (startReserved and (symbol not in validLetters) and symbol != ' ' and symbol != '\n'):
            tokens.append(('ID', symbol))
            startReserved = False            
        if (symbol in startReservedLetters and not startReserved):
            startReserved = True
        
        # Transition to the next state when the state has a transition for the symbol
        if symbol in moore.transitions[state]:
            output = moore.transitions[state][symbol]       
        # Transition to the next state when the state has a empty transition  
        else:
            output = moore.transitions[moore.initial_state][symbol]
        
        # Number handling
        if output == 'q50':
          var += symbol

        # ! handling
        if output == 'q34':
            startReserved = False
        elif outputTable[output] != '':
            tokens.append((outputTable[output], symbol))
            startReserved = False
      
        # Update the state
        state = output
    # ID handling    
    else:
        var += symbol
        if var != '' and (symbol in inputAlphabet and (symbol not in validLetters or len(var) == 1)):
            if (symbol in validPosIdCharacters):                
                output = moore.transitions[moore.initial_state][symbol]
                tokens.append(('ID', var))
                tokens.append((outputTable[output], symbol))
                var = ''
                startReserved = False

    # Update the previous symbol
    previousSymbol = symbol
    
  # filter '' tokens
  tokens = list(filter(lambda x: x[0] != '', tokens))
          
  return tokens

def main():
    check_cm = False
    check_key = False
    
    for idx, arg in enumerate(sys.argv):
        # print("Argument #{} is {}".format(idx, arg))
        aux = arg.split('.')
        if aux[-1] == 'cm':
            check_cm = True
            idx_cm = idx

        if(arg == "-k"):
            check_key = True
    
    # print ("No. of arguments passed is ", len(sys.argv))

    # Caso esteja comentado, nao passa no 1 teste do array 
    if(len(sys.argv) < 3):
         raise TypeError(error_handler.newError(check_key, 'ERR-LEX-USE'))

    if not check_cm:
      raise IOError(error_handler.newError(check_key, 'ERR-LEX-NOT-CM'))
    elif not os.path.exists(sys.argv[idx_cm]):
        raise IOError(error_handler.newError(check_key, 'ERR-LEX-FILE-NOT-EXISTS'))
    else:
        data = open(sys.argv[idx_cm])
        source_file = data.read()
        tokens = analysis(source_file)
        for token in tokens:
            if (token[0] == 'ERROR'):
                raise IOError(error_handler.newError(check_key, token[1]))
            else:
                print(token[0])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
    except (ValueError, TypeError):
        print(e)