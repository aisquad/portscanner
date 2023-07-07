from argparse import ArgumentParser
from datetime import datetime
from dateutil.relativedelta import relativedelta
from nmap import PortScanner, PortScannerAsync
from typing import Union


class Port:
    def __init__(self):
        self.host = ''
        self.hostname = ''
        self.hotname_type = ''
        self.protocol = ''
        self.port = ''
        self.name = ''
        self.state = ''
        self.product = ''
        self.extrainfo = ''
        self.reason = ''
        self.version = ''
        self.conf = ''
        self.cpe = ''

    def __repr__(self):
        return f'<Port {self.port} {self.state} {self.name} {self.reason}>'

    def set(self, items):
        for k, v in items.items():
            if hasattr(self, k):
                setattr(self, k, v)


class Scanner:
    def __init__(self):
        self._nmap: Union[None, PortScanner, PortScannerAsync] = None
        self.target = args.ip
        self.sep = '-' * 15
        self._dispatch()
        self._min_port = 0
        self._max_port = 65_535

    def _dispatch(self):
        if any([args.asynch, args.async_open]):
            self._nmap = PortScannerAsync()
        else:
            self._nmap = PortScanner()

    def network_status(self):
        self._nmap.scan(hosts=self.target, arguments='-n -sP -PE -PA21,23,80,3389')
        for host, status in ((_, self._nmap[_]['status']['state']) for _ in self._nmap.all_hosts()):
            print(f"{host}:{status}")

    def open_ports(self):
        start = datetime.now()
        first = args.start if args.start >= self._min_port else self._min_port
        last = args.start if args.start <= self._max_port else self._max_port
        if first > last:
            first, last = last, first
        last = last + 1

        if not args.only_open:
            open_ports = []
            for _ in range(first, last):
                res = self._nmap.scan(self.target, str(_))
                state = res['scan'][self.target]['tcp'][_]['state']
                print(f'port {_} is {state}')
                if state == 'open':
                    open_ports.append(_)
            print(f"SUMMARY: open ports ({len(open_ports)}): {open_ports}")
        else:
            for _ in range(first, last):
                res = self._nmap.scan(self.target, str(_))
                state = res['scan'][self.target]['tcp'][_]['state']
                if state == 'open':
                    print(f'port {_} is {state}')
        end = datetime.now()
        et = relativedelta(end, start)
        print(f'SCANNED PORTS ({args.end - args.start}): FROM {args.start} TO {args.end}.')
        print(f'ELAPSED TIME: {et.hours}h {et.minutes}m {et.seconds}s {et.microseconds}μs.')

    def open_ports(self):
        start = datetime.now()
        first = args.start if args.start >= self._min_port else self._min_port
        last = args.start if args.start <= self._max_port else self._max_port
        if first > last:
            first, last = last, first
        last = last + 1

        for _ in range(first, last):
            res = self._nmap.scan(self.target, str(_))
            state = res['scan'][self.target]['tcp'][_]['state']
            if state == 'open':
                print(f'port {_} is {state}')
        end = datetime.now()
        et = relativedelta(end, start)
        print(f'SCANNED PORTS ({args.end - args.start}): FROM {args.start} TO {args.end}.')
        print(f'ELAPSED TIME: {et.hours}h {et.minutes}m {et.seconds}s {et.microseconds}μs.')

    def simple(self):
        print(f'scanning... {args.ip}')
        start = datetime.now()
        self._nmap.scan(args.ip)
        end = datetime.now()
        print(self._nmap.all_hosts())
        et = relativedelta(end, start)
        print(f'{et.minutes}m {et.seconds}s {et.microseconds}μs')

    def _callback(self, host, scan):
        print(self.sep)
        print(host, scan)

    def async_scan(self):
        self._nmap.scan(hosts=self.target, arguments='-sP', callback=self._callback)
        while self._nmap.still_scanning():
            print("Waiting >>>")
            self._nmap.wait(args.wait)

    def async_open_ports(self):
        self._nmap.scan(hosts=self.target, arguments='-O -v', callback=self._callback)
        while self._nmap.still_scanning():
            print("Waiting >>>")
            self._nmap.wait(args.wait)

    def test(self):
        self._nmap.scan(hosts=self.target, arguments='-O -v')
        csv = self._nmap.csv()
        data = csv.splitlines()
        headers = data[0].split(';')
        ports = []
        for line in data[1:]:
            port = Port()
            port.set({k: v for k, v in zip(headers, line.split(';'))})
            ports.append(port)

        print(ports)


if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-a', '--asynch', dest='asynch', action="store_true")
    arg_parser.add_argument('-A', '--asyncopen', dest='async_open', action="store_true")
    arg_parser.add_argument('-e', '--end', dest='end', type=int, default=65535)
    arg_parser.add_argument('-i', '--ip', dest='ip', default='192.168.0.0/24')
    arg_parser.add_argument('-n', '--nstat', dest='nstat', action="store_true")
    arg_parser.add_argument('-o', '--open', dest='open', action="store_true")
    arg_parser.add_argument('-O', '--onlyopen', dest='only_open', action="store_true")
    arg_parser.add_argument('-s', '--simple', dest='simple', action="store_true")
    arg_parser.add_argument('-S', '--start', dest='start', type=int, default=0)
    arg_parser.add_argument('-T', '--test', dest='test', action="store_true")
    arg_parser.add_argument('-w', '--wait', dest='wait', type=int, default=5)
    args = arg_parser.parse_args()
    scanner = Scanner()
    if args.simple:
        scanner.simple()
    elif args.nstat:
        scanner.network_status()
    elif args.open:
        scanner.open_ports()
    elif args.async_open:
        scanner.async_open_ports()
    elif args.asynch:
        scanner.async_scan()
    elif args.test:
        scanner.test()
