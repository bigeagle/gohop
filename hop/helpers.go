/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Justin Wong <justin.w.xd@gmail.com>
 *
 */

package hop

import (
    "math/rand"
    "net"
)

func mac2uint64(mac net.HardwareAddr) (i uint64) {
    i = 0
    for _, a := range ([]byte)(mac) {
        i = (i << 8) + uint64(a)
    }
    return i
}

func ip4_uint32(ip net.IP) (i uint32) {
    i = 0
    for _, a := range ip {
        i = (i << 8) + uint32(a)
    }
    return i
}

func ip4_uint64(ip net.IP) (i uint64) {
    i = 0
    for _, a := range ip {
        i = (i << 8) + uint64(a)
    }
    return i
}

func randAddr(a []*hUDPAddr) *hUDPAddr {
    i := rand.Intn(len(a))
    return a[i]
}
