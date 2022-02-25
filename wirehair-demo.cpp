#undef NDEBUG
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <set>
#include <thread>
using namespace std::chrono_literals;
using std::this_thread::sleep_for;

#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <wirehair/wirehair.h>

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/ostream.h>
using fmt::format;
template <> struct fmt::formatter<boost::asio::ip::udp::endpoint> : fmt::ostream_formatter { };
template <> struct fmt::formatter<boost::uuids::uuid>             : fmt::ostream_formatter { };
template <> struct fmt::formatter<std::filesystem::path>          : fmt::ostream_formatter { };

static std::ostream debug(nullptr /*std::cout.rdbuf()*/);

namespace WirehairTransfer {
    namespace asio = boost::asio;
    namespace fs   = std::filesystem;
    using asio::ip::udp;
    using boost::uuids::uuid;
    using boost::system::error_code;

    static constexpr int      PACKET_SIZE  = 1400;
    static constexpr uint16_t DEFAULT_PORT = 9797;

    namespace /*protocol*/ {
        constexpr auto MAX_UDP_LENGTH =
            8192; // see https://stackoverflow.com/a/1098940/85371

        template <typename PacketType>
            constexpr bool valid_packet = [] {
                static_assert(std::is_trivial_v<PacketType>);
                static_assert(std::is_standard_layout_v<PacketType>);
                static_assert(sizeof(PacketType) <= MAX_UDP_LENGTH);
                return true;
            }();

#pragma pack(push, 1)
        struct packet_common {
            boost::endian::big_uint32_t magic;
            uuid                        xfer_id;
        };

        struct file_info {
            packet_common                  common;
            boost::endian::big_uint64_t    file_length;
            std::array<char, PATH_MAX + 1> name;

            enum : unsigned {
                MAGIC     = 0xDEFACED,
                HEADERLEN = sizeof(common) + sizeof(file_length),
            };
        };

        struct packet_info {
            packet_common                    common;
            boost::endian::big_uint32_t      block_length, id;
            std::array<uint8_t, PACKET_SIZE> block;
            enum : unsigned {
                MAGIC     = static_cast<unsigned>(~0xDEFACED),
                HEADERLEN = sizeof(common) + sizeof(block_length) + sizeof(id)
            };
        };

        struct any_packet_buffer {
            packet_common common;
            std::array<  //
                uint8_t, //
                MAX_UDP_LENGTH - sizeof(packet_common)>
                    opaque_buffer;
        };
#pragma pack(pop)
        static_assert(valid_packet<packet_common>);
        static_assert(valid_packet<file_info>);
        static_assert(valid_packet<packet_info>);
        static_assert(valid_packet<any_packet_buffer>);
        static_assert(MAX_UDP_LENGTH == sizeof(any_packet_buffer));

        // Rule Of Zero, please:
        struct WHFree {
            void operator()(WirehairCodec c) const { wirehair_free(c); }
        };

        using CodecPtr = std::unique_ptr<WirehairCodec_t, WHFree>;
    } // namespace

    using executor_type = asio::thread_pool::executor_type;

    struct AsyncReceiver : std::enable_shared_from_this<AsyncReceiver> {

        struct Transfer {
            std::string   name;
            udp::endpoint sender;
            size_t        file_length;
            CodecPtr      decoder;
            size_t        blocks_received = 0;
        };

        using CommitFunction = std::function<void(uuid, Transfer)>;
        using Transfers      = std::map<uuid, Transfer>;
        using Stats          = std::map<uuid, unsigned>;

        AsyncReceiver(executor_type ex, CommitFunction commit, uint16_t port = DEFAULT_PORT)
            : executor_(ex)
            , commit_(std::move(commit))
            , port_(port)
        {
            socket_.bind({{}, port_});
        }

        void start() {
            dispatch(strand_, [self = shared_from_this()] { self->do_receive(); });
        }

        void cancel() {
            dispatch(strand_, [self = shared_from_this()] { self->do_cancel(); });
        }

      private:
        void do_receive()
        {
            socket_.async_receive_from(
                    asio::buffer(&incoming_, sizeof(incoming_)), sender_,
                    boost::bind(&AsyncReceiver::on_incoming, shared_from_this(),
                        asio::placeholders::error,
                        asio::placeholders::bytes_transferred));
        }

        void do_cancel() { socket_.cancel(); }

        void on_incoming(error_code ec, size_t n)
        {
            any_packet_buffer current = incoming_;
            udp::endpoint     sender  = sender_;
            incoming_                 = {};

            if (ec != asio::error::operation_aborted) {
                do_receive();
            }

            if (!ec && n > file_info::HEADERLEN &&
                    current.common.magic == file_info::MAGIC) {
                auto& fi = reinterpret_cast<file_info&>(current);

                Transfer xfer{
                    std::string(fi.name.data(), // maybe not zero terminated
                            strnlen(fi.name.data(), fi.name.max_size())),
                        sender,
                        fi.file_length,
                        CodecPtr(wirehair_decoder_create(nullptr, fi.file_length,
                                    PACKET_SIZE)),
                };

                if (!xfer.decoder)
                    throw std::runtime_error("wirehair_decoder_create");

                std::cout << format(
                        "CLIENT Receiving {} file_length {} name {} from {}\n",
                        fi.common.xfer_id, fi.file_length, xfer.name, xfer.sender);

                auto [_, ok] =
                    transfers_.emplace(fi.common.xfer_id, std::move(xfer));
                assert(ok && "duplicate xfer_id");
            } else if (!ec && n >= packet_info::HEADERLEN &&
                    current.common.magic == packet_info::MAGIC) {

                auto& packet = reinterpret_cast<packet_info&>(current);
                debug << format("CLIENT Dump {} block_id {} block_length {} "
                        "raw bytes received {} HEADERS {}\n",
                        packet.common.xfer_id, packet.id,
                        packet.block_length, n, packet_info::HEADERLEN);
                assert(n == packet_info::HEADERLEN + packet.block_length);

                auto it = transfers_.find(packet.common.xfer_id);
                if (it == transfers_.end()) {
                    if (completed_.contains(packet.common.xfer_id)) {
                        redundant_[packet.common.xfer_id]++;
                        debug << format(
                            "CLIENT redundant packet for completed {}\n",
                            packet.common.xfer_id);
                    } else {
                        dropped_[packet.common.xfer_id]++;
                        debug
                            << format("CLIENT Packet for unknown transfer {}\n",
                                      packet.common.xfer_id);
                    }
                    return;
                } else {
                    auto& [xfer_id, xfer] = *it;
                    xfer.blocks_received += 1;
                    debug << format("CLIENT Sender {} xfer sender {}\n", sender,
                                    xfer.sender);
                    assert(sender == xfer.sender); // optional requirement?

                    debug << format(
                        "CLIENT (Incoming block_length {} for {} from {})\n",
                        packet.block_length, xfer_id, sender);

                    // Attempt decode
                    switch (wirehair_decode(xfer.decoder.get(), packet.id,
                                            packet.block.data(),
                                            packet.block_length)) //
                    {
                        case Wirehair_NeedMore: return;
                        case Wirehair_Success: break;
                        default: throw std::runtime_error("wirehair_decode");
                    }
                }

                // remove from transfers_ map
                auto xfer_id = it->first;
                auto xfer    = std::move(it->second); // pilfer
                completed_.emplace(xfer_id, xfer.blocks_received);
                transfers_.erase(it);

                std::cout << format("CLIENT Receive completed for {}\n", xfer_id);

                // commit operation off-strand
                defer(executor_,
                      [=, commit = this->commit_, xfer = std::move(xfer)]() mutable {
                          commit(xfer_id, std::move(xfer));
                      });
            } else {
                if (n && ec != asio::error::operation_aborted)
                    std::cout << format(
                        "CLIENT Discarded {} raw bytes magic "
                        "{:#0X} from {} ({})\n",
                        n, n > 4 ? (uint32_t)current.common.magic : 0u, sender,
                        ec.message());
            }
        }

      private:
        using strand_type = asio::strand<executor_type>;
        using sock_t      = asio::basic_datagram_socket<udp, strand_type>;

        executor_type  executor_;
        strand_type    strand_{executor_};
        sock_t         socket_{strand_, udp::v4()};
        CommitFunction commit_;
        uint16_t       port_;

        any_packet_buffer incoming_;
        udp::endpoint     sender_;

        Transfers transfers_;
        Stats     completed_, redundant_, dropped_;

        auto sync_get(auto member) {
            using R = std::decay_t<decltype(
                std::invoke(member, static_cast<AsyncReceiver*>(nullptr)))>;
            return dispatch( //
                       strand_,
                       std::packaged_task<R()>(
                           [self = shared_from_this(), member] {
                               return std::move(std::invoke(member, self));
                           }))
                .get();
        }

        size_t get_in_progress() const { return transfers_.size(); }

      public:
        size_t    in_progress() { return sync_get(&AsyncReceiver::get_in_progress); }
        Transfers partials()    { return sync_get(&AsyncReceiver::transfers_);      }
        Stats     completed()   { return sync_get(&AsyncReceiver::completed_);      }
        Stats     dropped()     { return sync_get(&AsyncReceiver::dropped_);        }
        Stats     redundant()   { return sync_get(&AsyncReceiver::redundant_);      }
    };

    struct FileCommitter {
        fs::path relative_path;

        void operator()(uuid xfer_id, AsyncReceiver::Transfer xfer) const
        {
            auto spec = // be safe interpreting output name
                fs::relative(
                    weakly_canonical(
                        relative_path /
                        fs::path(xfer.name).lexically_normal().relative_path()),
                    relative_path);

            if (spec.empty())
                throw std::runtime_error("invalid file specification " +
                                         spec.native());

            // Recover original data on decoder side
            if (std::vector<uint8_t> decoded(xfer.file_length);
                Wirehair_Success !=
                wirehair_recover(xfer.decoder.get(), decoded.data(),
                                 decoded.size())) //
            {
                throw std::runtime_error("wirehair_recover");
            } else {
                auto target = relative_path / spec;
                fs::create_directories(target.parent_path());

                debug << format("COMMIT Decoding to {} for {}\n", target,
                                xfer_id);
                std::ofstream(target, std::ios::binary)
                    .write(reinterpret_cast<char const*>(decoded.data()),
                           static_cast<std::streamsize>(decoded.size()));
            }
        }
    };

    struct Sender {
        Sender(asio::any_io_executor ex, uint16_t port = DEFAULT_PORT)
            : socket_(ex, udp::v4())
            , port_(port)
        {
        }

        bool send(fs::path filespec)
        {
            std::ifstream              ifs(filespec, std::ios::binary);
            std::vector<uint8_t> const contents(
                std::istreambuf_iterator<char>(ifs), {});
            ifs.close();
            assert(contents.size() == fs::file_size(filespec));

            file_info fi{}; // value-initializes all members
            fi.common.magic   = file_info::MAGIC;
            fi.common.xfer_id = boost::uuids::random_generator{}();
            fi.file_length    = contents.size();
            assert(strlen(filespec.c_str()) < fi.name.max_size());
            strncpy(fi.name.data(), filespec.c_str(), fi.name.max_size() - 1);

            // Create encoder
            encoder_.reset(wirehair_encoder_create(
                nullptr, contents.data(), contents.size(), PACKET_SIZE));
            if (!encoder_) {
                // likely contents too small; TODO create fallback encoding
                throw std::runtime_error("wirehair_encoder_create");
            }

            socket_.send_to(asio::buffer(&fi, sizeof(fi)), {{}, port_});
            debug << format("SERVER (Sent file_info magic {:#0X} for {})\n",
                            fi.common.magic, fi.common.xfer_id);

            auto N = contents.size() / PACKET_SIZE + 1;
            N      = (N * 10) / 9; // ~10% redundancy

            std::cout << format("SERVER Sending {} of {} bytes in {} packets "
                                "of {} xfer_id {}\n",
                                filespec, contents.size(), N, PACKET_SIZE,
                                fi.common.xfer_id);

            for (unsigned block_id = 1; block_id <= N; ++block_id) {
                sleep_for(1ms);
                packet_info packet{};
                packet.common.magic   = packet_info::MAGIC;
                packet.common.xfer_id = fi.common.xfer_id;

                // Encode a packet
                uint32_t writeLen = 0;
                if (auto r = wirehair_encode(encoder_.get(), block_id,
                                             packet.block.data(),
                                             packet.block.size(), &writeLen);
                    r == Wirehair_Success) //
                {
                    packet.id           = block_id;
                    packet.block_length = writeLen;
                    auto buf            = asio::buffer(&packet,
                                            packet_info::HEADERLEN + writeLen);
                    socket_.send_to(buf, {{}, port_});
                    debug << format("SERVER (Sent block magic {:#0X} and {} "
                                    "(raw) bytes for {})\n",
                                    packet.common.magic, buf.size(),
                                    packet.common.xfer_id);
                } else {
                    throw std::runtime_error("wirehair_encode");
                }
            }

            debug << format("SERVER Send {} complete (xfer_id:{})\n", filespec,
                            fi.common.xfer_id);
            return true;
        }

      private:
        udp::socket socket_;
        uint16_t    port_;
        CodecPtr    encoder_{};
    };
}

int main(int argc, char** argv) {
    using namespace WirehairTransfer;

    std::cout << std::unitbuf;
    if (auto r = wirehair_init(); r != Wirehair_Success) {
        std::cout << format("Wirehair initialization failed: {}\n", r);
        return 1;
    }

    asio::thread_pool recv_threads(10), send_threads(4);

    auto client = std::make_shared<AsyncReceiver>(recv_threads.get_executor(),
                                                  FileCommitter{"assets/"});
    client->start();

    for (auto spec : std::vector(argv + 1, argv + argc))
        post(send_threads, [ex = send_threads.get_executor(), spec] {
            try {
                Sender{ex}.send(spec);
            } catch (std::exception const& e) {
                std::cout << format("Exception: {}\n", e.what());
            }
        });

    send_threads.join();

    {
        // some grace time to allow UDP stack to be drained
        auto now      = std::chrono::steady_clock::now;
        auto deadline = now() + 1s;
        while (now() < deadline) {
            if (auto n = client->in_progress()) {
                std::cout << format("{} transfers still in progress...\n", n);
                sleep_for(1ms);
            } else
                break;
        }

        std::cout << format("{}ms grace time remained before deadline\n",
                (deadline - now()) / 1ms);
    }

    // cancel any transfers still in progress
    client->cancel();

    for (auto& [id, xfer] : client->partials()) {
        std::cout << format("Canceled incomplete {}, {} ({})\n", id,
                            xfer.blocks_received, xfer.name);
    }
    std::cout << format("Completed transfers: {}\n", client->completed());
    std::cout << format("Missed transfers:    {}\n", client->dropped());
    std::cout << format("Ignored redundancy:  {}\n", client->redundant());

    // this *does* await completion of any files being recovered/commited,
    // because these operations are not canceled
    recv_threads.join();
}
