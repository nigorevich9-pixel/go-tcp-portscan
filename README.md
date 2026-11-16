# go-tcp-portscan

TCP connect-сканер на Go. Без raw-сокетов, без nmap — просто `net.Dial` пачкой, с лимитом параллельности.

Делал как библиотеку: можно дергать из своего кода. Рядом лежит маленький CLI `cmd/scan`, им обычно и проверяю локально.

Сканировать чужие хосты без разрешения нельзя. Это не SYN-скан и не обход файрвола.

## Зависимости

Только стандартная библиотека. В `go.mod` указан Go 1.22.

```
go get github.com/nigorevich9-pixel/go-tcp-portscan
```

## Библиотека

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/nigorevich9-pixel/go-tcp-portscan"
)

func main() {
    s, err := portscan.New(
        portscan.WithWorkers(32),
        portscan.WithTimeout(800*time.Millisecond),
    )
    if err != nil {
        panic(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    ports := portscan.Union(portscan.List(22, 80, 443), portscan.Range(8000, 8010))
    ch, err := s.Scan(ctx, []string{"127.0.0.1"}, ports)
    if err != nil {
        panic(err)
    }

    for r := range ch {
        fmt.Printf("%s:%d %s\n", r.IP, r.Port, r.State)
    }
}
```

Что важно:

- хосты: ipv4, ipv6 (`::1`), обычные dns-имена
- если у имени несколько адресов — проверяются все
- dns падает целиком до начала коннектов, частичного скана нет
- результаты приходят как получится, порядок не обещаю
- лимит воркеров общий на экземпляр `Scanner`, даже если `Scan` вызвали несколько раз параллельно
- канал небуферизованный: перестал читать — отмени контекст, иначе горутины ждут отправки

Состояния: `open`, `closed` (ECONNREFUSED), `timeout`, `unreachable`, `canceled`, `error`.

По дефолту 64 воркера и таймаут коннекта 1 секунда.

## CLI

```
go run ./cmd/scan -p 22,80,443,8000-8010 127.0.0.1
```

Флаги: `-p` порты, `-n` параллельность, `-timeout` на один dial.

## Тесты

```
go test ./...
go test -race ./...
```

Внешние адреса в тестах не дергаю — либо localhost, либо заглушки dial/dns.

## Лицензия

MIT.
