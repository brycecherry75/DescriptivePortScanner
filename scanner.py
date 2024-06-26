import argparse, socket, os, csv

PortDescriptorFile = "ports.csv"
PortDescriptorRangeFile = "ports_ranges.csv"

def PrintPortDescription(PORT, PortDescription):
  global PortsFileValid
  if PortsFileValid == True:
    print("Port", PORT, "is open - service is:", PortDescription)
  else:
    print("Port", PORT, "is open")

def FindPortDescription(PORT):
  global PortsFileValid
  PortDescription = "Unknown"
  if PortsFileValid == True:
    fields = []
    rows = []
    with open(PortDescriptorFile, 'r') as csvfile:
      PortReader = csv.reader(csvfile)
      for row in PortReader:
        rows.append(row)
      LineCount = PortReader.line_num
      for row in rows[:LineCount]:
        if PortsFileValid == True and PORT == int(row[0]):
          PrintPortDescription(PORT, row[1])
          PortDescription = row[1]
  return PortDescription

def FindPortRangeDescription(PORT):
  global PortsFileValid
  PortDescription = "Unknown"
  if PortsFileValid == True:
    fields = []
    rows = []
    with open(PortDescriptorRangeFile, 'r') as csvfile:
      PortReader = csv.reader(csvfile)
      for row in PortReader:
        rows.append(row)
      LineCount = PortReader.line_num
      for row in rows[:LineCount]:
        if PortsFileValid == True and PORT >= int(row[0]) and PORT <= int(row[1]):
          PrintPortDescription(PORT, row[2])
          PortDescription = row[2]
  return PortDescription

def ScanPort(HOST, PORT):
  s = None
  for res in socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM):
    af, socktype, proto, canonname, sa = res
    try:
      s = socket.socket(af, socktype, proto)
    except OSError as msg:
      s = None
      break
    try:
      s.connect(sa)
    except OSError as msg:
      s.close()
      s = None
      break
  if s is not None:
    return True
  else:
    return False

def ScanKnownPorts(HOST, CheckValidPortsFile):
  global PortsFileValid
  KnownPortsFound = False
  if os.path.isfile(PortDescriptorFile) and os.path.isfile(PortDescriptorRangeFile):
    fields_ports = []
    rows_ports = []
    with open(PortDescriptorFile, 'r') as csvfile:
      PortReader = csv.reader(csvfile)
      for row_ports in PortReader:
        rows_ports.append(row_ports)
      LineCount = PortReader.line_num
      CurrentLine = 0
      for row_ports in rows_ports[:LineCount]:
        CurrentLine += 1
        if CheckValidPortsFile == True:
          if len(row_ports) < 2:
            print("Two fields not found in line", CurrentLine, "of", PortDescriptorFile)
            PortsFileValid = False
            break
          try:
            temp = int(row_ports[0])
          except:
            print("Port not a number in first column of line", CurrentLine, "in", PortDescriptorFile)
            PortsFileValid = False
            break
          if int(row_ports[0]) < 0 or int(row_ports[0]) > 65535:
            print("Port number in first column of line", CurrentLine, "out of range in", PortDescriptorFile)
            PortsFileValid = False
            break
        elif PortsFileValid == True:
          PORT = int(row_ports[0])
          if ScanPort(HOST, PORT) == True:
            PortDescription = row_ports[1]
            PrintPortDescription(PORT, PortDescription)
            KnownPortsFound = True
    fields_ports_ranges = []
    rows_ports_ranges = []
    with open(PortDescriptorRangeFile, 'r') as csvfile:
      PortReader = csv.reader(csvfile)
      for row_ports_ranges in PortReader:
        rows_ports_ranges.append(row_ports_ranges)
      LineCount = PortReader.line_num
      CurrentLine = 0
      for row_ports_ranges in rows_ports_ranges[:LineCount]:
        CurrentLine += 1
        if CheckValidPortsFile == True:
          if len(row_ports_ranges) < 3:
            print("Three fields not found in line", CurrentLine, "of", PortDescriptorRangeFile)
            PortsFileValid = False
            break
          try:
            temp = int(row_ports_ranges[0])
          except:
            print("Port not a number in first column of line", CurrentLine, "in", PortDescriptorRangeFile)
            PortsFileValid = False
            break
          try:
            temp = int(row_ports_ranges[1])
          except:
            print("Port not a number in second column of line", CurrentLine, "in", PortDescriptorRangeFile)
            PortsFileValid = False
            break
          if int(row_ports_ranges[0]) < 0 or int(row_ports_ranges[0]) > 65535:
            print("Port number in first column of line", CurrentLine, "out of range in", PortDescriptorRangeFile)
            PortsFileValid = False
            break
          if int(row_ports_ranges[1]) < 0 or int(row_ports_ranges[1]) > 65535:
            print("Port number in second column of line", CurrentLine, "out of range in", PortDescriptorRangeFile)
            PortsFileValid = False
            break
          if int(row_ports_ranges[0]) > int(row_ports_ranges[1]):
            print("Port ranges need to be swapped between first and second columns in line", CurrentLine, "in", PortDescriptorRangeFile)
            PortsFileValid = False
            break
        elif PortsFileValid == True:
          PORT_start = int(row_ports_ranges[0])
          PORT_end = int(row_ports_ranges[1])
          for PORT in range ((PORT_end - PORT_start) + 1):
            if ScanPort(HOST, (PORT + PORT_start)) == True:
              PortDescription = row_ports_ranges[2]
              PrintPortDescription((PORT + PORT_start), PortDescription)
              KnownPortsFound = True
  else:
    PortsFileValid = False
  return KnownPortsFound

if __name__ == '__main__':
  parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
  parser.add_argument("--host", required='yes', help="Host to check for open ports")
  parser.add_argument("--porttimeout", type=float, default=0.1, help="Port scan timeout in seconds (default: 0.1)")
  parser.add_argument("--portstart", type=int, default=0, help="Port start (default: 0)")
  parser.add_argument("--portstop", type=int, default=65535, help="Port stop (default: 65535)")
  parser.add_argument("--knownportsonly", action='store_true', help=("Scan only known ports as described in " + PortDescriptorFile + " and " + PortDescriptorRangeFile))
  args = parser.parse_args()
  HOST = args.host
  global PortsFileValid
  global UnknownPortsFound
  UnknownPortsFound = False
  PortsFileValid = True
  socket.setdefaulttimeout(args.porttimeout)
  ScanKnownPorts(HOST, True)
  KnownPortsFound = False
  if PortsFileValid == False:
    print("No port descriptions will be displayed")
  if args.knownportsonly:
    if KnownPortsFound == True:
      ScanKnownPorts(args.host, False)
    else:
      KnownPortsFound = ScanKnownPorts(args.host, False)
  else:
    PortStart = args.portstart
    PortStop = args.portstop
    if PortStop < PortStart:
      PortStart = args.portstop
      PortStop = args.portstart
    if PortStart < 0:
      PortStart = 0
      print("WARNING: Port start is now 0")
    elif PortStart > 65535:
      PortStart = 65535
      print("WARNING: Port start is now 65535")
    if PortStop < 0:
      PortStop = 0
      print("WARNING: Port stop is now 0")
    elif PortStop > 65535:
      PortStop = 65535
      print("WARNING: Port stop is now 65535")
    for PORT in range ((PortStop + 1)):
      if PORT >= PortStart and ScanPort(HOST, PORT) == True:
        if PortsFileValid == True:
          DescriptionMatches = 0
          PortDescription = FindPortDescription(PORT)
          if PortDescription != "Unknown":
            DescriptionMatches += 1
            KnownPortsFound = True
          PortDescription = FindPortRangeDescription(PORT)
          if PortDescription != "Unknown":
            DescriptionMatches += 1
            KnownPortsFound = True
          if DescriptionMatches == 0:
            UnknownPortsFound = True
            PrintPortDescription(PORT, "Unknown")
        else:
          PrintPortDescription(PORT, "Unknown")
  if KnownPortsFound == False:
    print("No open ports have been found at", args.host)
  elif PortsFileValid == True and UnknownPortsFound == True:
    print("NOTE: Unknown open ports have been found at", args.host)