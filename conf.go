package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

type peer struct {
	dialer *net.Dialer

	pubKey string

	addr   string
	ipPort string
}

func newPeerEndpoint() (*peer, error) {
	pubKey, err := base64.StdEncoding.DecodeString(opts.PeerKey)
	if err != nil {
		return nil, fmt.Errorf("parse peer public key: %w", err)
	}

	p := &peer{
		dialer: &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					dot := false
					if opts.DNS != "" {
						port := "53"
						if opts.DoT != "" {
							port = opts.DoT
							dot = true
						}
						address = net.JoinHostPort(opts.DNS, port)
					}
					logger.Verbosef("Using %s (DoT: %t) to resolve peer endpoint", address, dot)

					if !dot {
						var d net.Dialer
						return d.DialContext(ctx, network, address)
					}
					d := tls.Dialer{
						Config: &tls.Config{
							InsecureSkipVerify: true,
						},
					}
					return d.DialContext(ctx, "tcp", address)
				},
			},
		},
		pubKey: hex.EncodeToString(pubKey),
		addr:   opts.PeerEndpoint,
	}
	p.ipPort, err = p.resolveAddr()
	if err != nil {
		return nil, fmt.Errorf("resolve peer endpoint: %w", err)
	}
	return p, err
}

func (p *peer) initConf() string {
	conf := "public_key=" + p.pubKey + "\n"
	conf += "endpoint=" + p.ipPort + "\n"
	conf += "allowed_ip=0.0.0.0/0\n"
	conf += "allowed_ip=::/0\n"

	if opts.KeepaliveInterval > 0 {
		conf += fmt.Sprintf("persistent_keepalive_interval=%.f\n", opts.KeepaliveInterval.Seconds())
	}

	return conf
}

func (p *peer) updateConf() (string, bool) {
	newIPPort, err := p.resolveAddr()
	if err != nil {
		logger.Verbosef("Resolve peer endpoint: %v", err)
		return "", false
	}
	if p.ipPort == newIPPort {
		return "", false
	}
	p.ipPort = newIPPort
	logger.Verbosef("PeerEndpoint is changed to: %s", p.ipPort)

	conf := "public_key=" + p.pubKey + "\n"
	conf += "update_only=true\n"
	conf += "endpoint=" + p.ipPort + "\n"
	return conf, true
}

func (p *peer) resolveAddr() (string, error) {
	c, err := p.dialer.Dial("udp", p.addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.RemoteAddr().String(), nil
}

func ipcSet(dev *device.Device) error {
	privateKey, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse client private key: %w", err)
	}
	conf := "private_key=" + hex.EncodeToString(privateKey) + "\n"

	peer, err := newPeerEndpoint()
	if err != nil {
		return err
	}
	conf += peer.initConf()
	logger.Verbosef("Device config:\n%s", conf)

	if err := dev.IpcSet(conf); err != nil {
		return err
	}

	if peer.addr != peer.ipPort {
		go func() {
			c := time.Tick(opts.ResolveInterval)

			for range c {
				conf, needUpdate := peer.updateConf()
				if !needUpdate {
					continue
				}

				if err := dev.IpcSet(conf); err != nil {
					logger.Errorf("Config device: %v", err)
				}
			}
		}()
	}
	return nil
}
